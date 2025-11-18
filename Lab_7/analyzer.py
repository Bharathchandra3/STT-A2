import re
import sys
import os
from graphviz import Digraph

class CAnalyzer:
    def __init__(self, source_code):
        self.lines = source_code.split('\n')
        self.blocks = {}  # Map block_id -> list of code lines
        self.edges = []   # List of (src_id, dest_id)
        self.cfg_nodes = []
        
        # Reaching Definitions Data
        self.definitions = {} # Map def_id -> (var, line_num)
        self.block_gen = {}
        self.block_kill = {}
        self.block_in = {}
        self.block_out = {}

    def is_leader(self, line_idx, line):
        # Heuristic to find basic block leaders
        line = line.strip()
        if not line: return False
        
        # Previous line was a jump/branch
        if line_idx > 0:
            prev = self.lines[line_idx-1].strip()
            if prev.startswith('if') or prev.startswith('while') or prev.startswith('for') or prev.startswith('return') or '}' in prev:
                return True
        
        # Current line is a target or distinct structure start
        if line.startswith('if') or line.startswith('while') or line.startswith('for') or line.startswith('return') or line.startswith('case') or line.startswith('default'):
            return True
            
        return False

    def build_cfg(self):
        print("Building Basic Blocks...")
        leaders = [0]
        for i in range(1, len(self.lines)):
            if self.is_leader(i, self.lines[i]):
                leaders.append(i)
        leaders.sort()
        
        # Create Blocks
        for i in range(len(leaders)):
            start = leaders[i]
            end = leaders[i+1] if i + 1 < len(leaders) else len(self.lines)
            block_id = i + 1
            self.blocks[block_id] = self.lines[start:end]
            self.cfg_nodes.append(block_id)

        # Naive Edge Creation (Sequential flow + jumps)
        # This is a simplified logic for Lab purposes
        for bid in self.cfg_nodes:
            if bid + 1 in self.cfg_nodes:
                # Add sequential edge
                self.edges.append((bid, bid + 1))
            
            # Check last line for control flow to add back-edges or branches
            last_line = self.blocks[bid][-1].strip()
            if 'while' in last_line or 'for' in last_line:
                # Loop usually goes back to itself or next
                self.edges.append((bid, bid)) 

    def draw_cfg(self, filename):
        dot = Digraph(comment=f'CFG for {filename}')
        dot.attr(rankdir='TB')
        
        print(f"Generating CFG nodes for {filename}...")
        for bid, code in self.blocks.items():
            # Summary of block content (first 2 lines)
            label = f"Block {bid}\n" + "\n".join([l.strip()[:30] for l in code[:2] if l.strip()])
            dot.node(str(bid), label, shape='box')
            
        for src, dst in self.edges:
            dot.edge(str(src), str(dst))
            
        output_path = f"{filename}_cfg"
        dot.render(output_path, view=False, format='png')
        print(f"CFG saved to {output_path}.png")

    def calculate_complexity(self):
        # Cyclomatic Complexity = E - N + 2P
        E = len(self.edges)
        N = len(self.cfg_nodes)
        P = 1 # Single program
        cc = E - N + 2 * P
        print(f"Cyclomatic Complexity: {cc}")
        return cc

    def perform_reaching_definitions(self):
        print("Performing Reaching Definitions Analysis...")
        
        # 1. Identify all definitions (assignments)
        def_counter = 1
        block_defs = {bid: [] for bid in self.cfg_nodes} # bid -> list of (def_id, var)
        
        for bid, lines in self.blocks.items():
            for i, line in enumerate(lines):
                # Look for 'var = ...' pattern
                match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=', line)
                if match:
                    var = match.group(1)
                    # Ignore keywords used as vars (unlikely in C but good to be safe)
                    if var not in ['if', 'while', 'for', 'return']:
                        d_id = f"D{def_counter}"
                        self.definitions[d_id] = (var, line.strip())
                        block_defs[bid].append((d_id, var))
                        def_counter += 1

        # 2. Compute GEN and KILL sets
        all_defs = self.definitions.keys()
        
        for bid in self.cfg_nodes:
            gen = set()
            kill = set()
            
            # For Gen: The *last* definition of a variable in the block
            local_defs = block_defs[bid] # List of (did, var)
            seen_vars = set()
            
            # Process in reverse to find the "surviving" definition for GEN
            for d_id, var in reversed(local_defs):
                if var not in seen_vars:
                    gen.add(d_id)
                    seen_vars.add(var)
            
            # For Kill: All definitions of variables modified in this block
            vars_modified = {v for _, v in local_defs}
            for d_id, (d_var, _) in self.definitions.items():
                if d_var in vars_modified and d_id not in gen:
                    # Check if it's not the one generated by this block (already handled)
                    # Actually, Kill is ALL other definitions of these variables anywhere in program
                    kill.add(d_id)
            
            # Remove definitions generated in THIS block from KILL (technically Gen overrides them)
            # But standard definition: Kill = all other defs of var v
            # Refine Kill:
            kill = set()
            for d_id_outer, (var_outer, _) in self.definitions.items():
                if var_outer in vars_modified:
                    # If this definition is NOT in the current block's GEN set, it is killed
                    if d_id_outer not in gen:
                        kill.add(d_id_outer)

            self.block_gen[bid] = gen
            self.block_kill[bid] = kill
            
            # Initialize IN/OUT
            self.block_in[bid] = set()
            self.block_out[bid] = set()

        # 3. Iterative Solver
        changed = True
        iteration = 0
        while changed:
            changed = False
            iteration += 1
            print(f"  Iteration {iteration}...")
            
            for bid in self.cfg_nodes:
                # IN[B] = Union of OUT[P] for all predecessors P
                predecessors = [src for src, dst in self.edges if dst == bid]
                new_in = set()
                for p in predecessors:
                    new_in = new_in.union(self.block_out[p])
                
                # OUT[B] = GEN[B] U (IN[B] - KILL[B])
                # (In - Kill)
                surviving = new_in - self.block_kill[bid]
                new_out = self.block_gen[bid].union(surviving)
                
                if new_in != self.block_in[bid] or new_out != self.block_out[bid]:
                    self.block_in[bid] = new_in
                    self.block_out[bid] = new_out
                    changed = True
                    
        return iteration

    def print_report(self):
        print("\n" + "="*40)
        print("Reaching Definitions Report")
        print("="*40)
        print(f"{'Block':<10} | {'Gen':<15} | {'Kill':<15} | {'In':<20} | {'Out':<20}")
        print("-" * 90)
        for bid in self.cfg_nodes:
            s_gen = ", ".join(sorted(list(self.block_gen[bid])))
            s_kill = ", ".join(sorted(list(self.block_kill[bid])))
            s_in = ", ".join(sorted(list(self.block_in[bid])))
            s_out = ", ".join(sorted(list(self.block_out[bid])))
            print(f"{bid:<10} | {s_gen:<15} | {s_kill:<15} | {s_in:<20} | {s_out:<20}")

# Main Execution Handler
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <c_file>")
        sys.exit(1)

    filename = sys.argv[1]
    if not os.path.exists(filename):
        print(f"Error: File {filename} not found.")
        sys.exit(1)

    with open(filename, 'r') as f:
        code = f.read()

    print(f"Analyzing {filename}...")
    analyzer = CAnalyzer(code)
    analyzer.build_cfg()
    analyzer.draw_cfg(filename)
    analyzer.calculate_complexity()
    analyzer.perform_reaching_definitions()
    analyzer.print_report()
    print("\nAnalysis Done.")
