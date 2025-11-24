import ipaddress

class FirewallManager:
    def __init__(self):
        self.rule_list = [] # list of dictionaries: {"rule": int, "direction": "in"|"out"|"both", "address": String} per value

    # Function to add a rule
    def add_rule(self, rule, direction, addr): # add [rule] [-in|-out] addr

        if rule is None:
            rule = 1 # Default rule number

        if direction is None:
            direction = "both"   # Default direction is both

        # Check if rule number already exists
        if any(r["rule"] == rule for r in self.rule_list):
            for r in self.rule_list:
                if r["rule"] >= rule:
                    # Increment rule numbers of all following rules
                    r["rule"] += 1
        
        self.rule_list.append({"rule": rule, "direction": direction, "address": addr}) # Add the new rule

        self.rule_list.sort(key=lambda r : r["rule"]) # Sort rule list by rule number to maintain priority

        print(f"Added rule number {rule}: {direction} {addr}")

    def remove_rule(self, rule, direction):

        if direction is None:
            direction = "both" # Default direction is both

        rule_to_remove = next((r for r in self.rule_list if r["rule"] == rule), None) # Iterate through rule list to find rule to remove
        # Check if rule exists
        if rule_to_remove:
            
            # Case 1: Remove entire rule if directions match or specified direction is 'both'
            if rule_to_remove["direction"] == direction or direction == "both":
                self.rule_list.remove(rule_to_remove)
                print(f"Removed rule number {rule}")

            # Case 2: Remove only one direction from a 'both' rule
            elif rule_to_remove["direction"] == "both" and direction != "both":
                match direction:
                    case "in":
                        rule_to_remove.update({"direction": "out"})
                    case "out":
                        rule_to_remove.update({"direction": "in"})
                print(f"Removed rule number {rule}: {direction}")

            # If specified direction does not match rule's direction
            else:
                print(f"Error: Rule number {rule} does not match direction {direction}.")
        else: 
            print(f"Error: Rule number {rule} not found.")
    
    # Function to list rules with optional filters
    def list_rules(self, rule_filter, direction_filter, addr_filter): # list [rule] [-in|-out] [addr]
        if not self.rule_list:
            print("No firewall rules configured.")
            return
        
        print("Firewall Rules:")

        rules_to_list = []

        # Helper function to check if address is a range
        def is_addr_range(ip):
            return "-" in ip if ip else False

        # If addr is a single IP address
        if not is_addr_range(addr_filter): 
            
            # Iterate over rule list and skip rules that do not match filters
            for r in self.rule_list:
                if rule_filter is not None and r["rule"] != rule_filter:
                    continue
                if direction_filter is not None and (r["direction"] != direction_filter and r["direction"] != "both"):
                    continue
                if addr_filter is not None and r["address"] != addr_filter:
                    continue

                rules_to_list.append(r)

        # If addr is a range of IP addresses
        else:
            # Split addr into start and end IP addresses
            start_str, end_str = addr_filter.split("-")
            range_start = ipaddress.ip_address(start_str.strip())
            range_end   = ipaddress.ip_address(end_str.strip())

            for r in self.rule_list:
                if rule_filter is not None and r["rule"] != rule_filter:
                    continue
                if direction_filter is not None and (r["direction"] != direction_filter and r["direction"] != "both"):
                    continue
                if not is_addr_range(r["address"]): # If rule address is a single IP address, just check if it is within specified range
                    rule_ip = ipaddress.ip_address(r["address"])
                    if not (range_start <= rule_ip <= range_end):
                        continue
                else: # If rule address is a range, extract start and end IP addresses
                    start, end = r["address"].split("-")
                    rule_start = ipaddress.ip_address(start.strip())
                    rule_end   = ipaddress.ip_address(end.strip())

                    # Check if rule range is within specified range
                    if not (range_start <= rule_start and range_end >= rule_end):
                        continue

                rules_to_list.append(r)

        for r in rules_to_list:
            print(f"Rule {r['rule']}: {r['direction']} {r['address']}")
        
# Helper function to check if an IP address is valid
def is_valid_ip_or_range(ip):
    # Check if input is a single IP address and validate
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        pass

    # Check if input is a range e.g. 10.0.0.1 - 10.0.0.128
    if "-" in ip:
        range_parts = ip.split("-")
        if len(range_parts) != 2:
            return False

        start = range_parts[0].strip()
        end = range_parts[1].strip()

        # Validate both addresses in range
        try:
            range_start = ipaddress.ip_address(start)
            range_end = ipaddress.ip_address(end)
        except ValueError:
            return False

        # Return true if start address is less than or equal to end address
        return range_start <= range_end
        
    return False
        
# Function to handle command parsing
def parse_command(fw_manager, line):
    tokens = line.split()
    if not tokens:
        return
    
    # Extract command and arguments
    command = tokens[0]
    args = tokens[1:]

    # Initialise default values
    rule, direction, addr = None, None, None

    for arg in args:
        # direction
        if arg == "-in":
            direction = "in"
            continue
        if arg == "-out":
            direction = "out"
            continue

        # rule number
        if arg.isdigit():
            rule = int(arg)
            if rule < 1:
                print("Error: Invalid rule number.")
                return
            continue

        # IP address
        if is_valid_ip_or_range(arg):
            addr = arg
            continue

        print(f"Unrecognized argument: {arg}")
        return

    # Handle commands by case
    match command:
        case "add":
            if addr is not None: # Check that IP address is specified
                fw_manager.add_rule(rule, direction, addr)
            else:
                print("Error: A valid IP address must be specified to add a rule.")
                return

        case "remove":
            if rule is not None:
                fw_manager.remove_rule(rule, direction)
            else:
                print("Error: A rule number must be specified to remove a rule.")
                return
        
        case "list":
            fw_manager.list_rules(rule, direction, addr)
        
        case _:
            print(f"Unrecognized command: {command}")
            return

# Main function to run the firewall manager CLI
def main():
    fw = FirewallManager()
            
    print("Firewall Manager CLI")
    print("Type 'exit' to quit.")

    while(True):
        command_input = input()
        if command_input == "exit":
            print("Exited Firewall Manager CLI.")
            break
        parse_command(fw, command_input) # Call parsing function

if __name__ == "__main__":
    main()


