# Importing for the application
# try and except are used to catch potential errors
try:
    import requests
    import json
    import csv
    import os
    from tkinter import *
    from tkinter import messagebox, simpledialog, ttk

except ImportError as e:
    print("Error when importing:", e) # Print error message
    exit(1)  # Hard terminate


def fetch_data(start_date, end_date):
    """Get information using the NVD CVE Change History API."""
    try:
        # https://nvd.nist.gov/developers/vulnerabilities
        # EXAMPLE: pubStartDate - 2023-12-01T00:00:00.000, and pubEndDate - 2024-02-10T00:00:00.000
        base_url = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
        params = {
            "changeStartDate": start_date,
            "changeEndDate": end_date
        }
        response = requests.get(base_url, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json()
    except Exception as e:
        print(f"Error fetching data: {e}")
        return None

def save_json(data, filename='cveCH_raw.json'):
    """Put the retrieved data in a JSON file."""
    if data is not None:  # Check if data is not None before proceeding
        try:
            with open(filename, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            print(f"Error saving JSON data: {e}")

def parse_to_csv(data, filename='cveCH_parsed.csv'):
    """Parse JSON data, save it to CSV, and handle any missing keys."""
    if data is not None:  # Check if data is not None before proceeding
        try:
            with open(filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(['CVE ID', 'EVENT NAME', 'CVE CHANGE ID', 'SOURCE IDENTIFIER', 'CREATED DATE', 'ACTION', 'TYPE', 'OLD VALUE', 'NEW VALUE'])

                for entry in data.get('cveChanges', []):
                    change = entry.get('change', {})
                    for detail in change.get('details', []):
                        writer.writerow([
                            change.get('cveId', ''),
                            change.get('eventName', ''),
                            change.get('cveChangeId', ''),
                            change.get('sourceIdentifier', ''),
                            change.get('created', ''),
                            detail.get('action', ''),
                            detail.get('type', ''),
                            detail.get('oldValue', 'N/A'),  # Use 'N/A' for missing old values
                            detail.get('newValue', 'N/A')  # Use 'N/A' for missing new values
                        ])
        except Exception as e:
            print(f"Error parsing data to CSV: {e}")

def request_dates():
    """Ask the user for the start and finish dates."""
    try:
        root = Tk()
        start_date = simpledialog.askstring("Input", "Enter start date (YYYY-MM-DDTHH:MM:SSZ):", parent=root)
        end_date = simpledialog.askstring("Input", "Enter end date (YYYY-MM-DDTHH:MM:SSZ):", parent=root)
        root.destroy()
        if start_date is None or end_date is None:
            raise ValueError("Start date or end date not provided")
        return start_date, end_date
    except Exception as e:
        print(f"Error while requesting dates: {e}")
        return None, None
    


def update_table(tree, data, filter_type):
    """According to the chosen filter, update the table."""
    try:
        for item in tree.get_children():
            tree.delete(item)
        populate_all_table(tree, data, filter_type)
    except Exception as e:
        print(f"Error updating table: {e}")



def display_gui(data, filter_type=None):
    """Show the GUI to view the parsed data."""
    try:
        root = Tk()
        root.title("CVE Changes Display")

        tree = ttk.Treeview(root, show='headings')  # Use 'headings' to show only column titles

        # Define columns based on the context of the filter type
        if filter_type == "Added":
            tree['columns'] = ('Action', 'Type', 'Old Value', 'New Value')
            tree.heading('Action', text='Action')
            tree.heading('Type', text='Type')
            tree.heading('Old Value', text='Old Value')
            tree.heading('New Value', text='New Value')

            tree.column('Action', width=100)
            tree.column('Type', width=100)
            tree.column('Old Value', width=150)
            tree.column('New Value', width=150)
            populate_added_table(tree, data)

        elif filter_type == "Changed":
            tree['columns'] = ('Action', 'Type', 'Old Value', 'New Value')
            tree.heading('Action', text='Action')
            tree.heading('Type', text='Type')
            tree.heading('Old Value', text='Old Value')
            tree.heading('New Value', text='New Value')

            tree.column('Action', width=100)
            tree.column('Type', width=100)
            tree.column('Old Value', width=150)
            tree.column('New Value', width=150)
            populate_changed_table(tree, data)

        else:
            # Setup for "All" which includes all columns and filter dropdown
            tree['columns'] = ('CVE ID', 'Event Name', 'Change ID', 'Source', 'Created', 'Action', 'Type', 'Old Value', 'New Value')
            tree.heading('CVE ID', text='CVE ID')
            tree.heading('Event Name', text='Event Name')
            tree.heading('Change ID', text='Change ID')
            tree.heading('Source', text='Source')
            tree.heading('Created', text='Created')
            tree.heading('Action', text='Action')
            tree.heading('Type', text='Type')
            tree.heading('Old Value', text='Old Value')
            tree.heading('New Value', text='New Value')

            tree.column('CVE ID', width=100)
            tree.column('Event Name', width=150)
            tree.column('Change ID', width=100)
            tree.column('Source', width=100)
            tree.column('Created', width=150)
            tree.column('Action', width=100)
            tree.column('Type', width=100)
            tree.column('Old Value', width=150)
            tree.column('New Value', width=150)
            
            populate_all_table(tree, data)  # Populate the table with all entries initially

            # Filter options for the "All" table
            filter_frame = Frame(root)
            filter_frame.pack(pady=10)

            filter_var = StringVar(root)
            filter_var.set("All")
            filter_dropdown = OptionMenu(filter_frame, filter_var, "All", "Added", "Changed", command=lambda choice: update_table(tree, data, filter_var.get()))
            filter_dropdown.pack()

        tree.pack(expand=YES, fill=BOTH)
        root.mainloop()
    except Exception as e:
        print(f"Error displaying GUI: {e}")



def populate_added_table(tree, data):
    """Add entries to the 'Added' table."""
    try:
        for item in tree.get_children():
            tree.delete(item)  # Clear existing items before repopulating
        index = 1
        for entry in data['cveChanges']:
            change = entry['change']
            for detail in change['details']:
                if detail['action'] == "Added":
                    values = (
                        detail['action'],
                        detail['type'],
                        'N/A',  # Old Value typically not applicable for 'Added'
                        detail.get('newValue', 'N/A')  # Display New Value
                    )
                    tree.insert('', 'end', iid=index, text=str(index), values=values)
                    index += 1
    except Exception as e:
        print(f"Error populating 'Added' table: {e}")



def populate_changed_table(tree, data):
    """Add 'Changed' entries to the 'Changed' table."""
    try:
        for item in tree.get_children():
            tree.delete(item)  # Clear existing items before repopulating
        index = 1
        for entry in data['cveChanges']:
            change = entry['change']
            for detail in change['details']:
                if detail['action'] == "Changed":
                    values = (
                        detail['action'],
                        detail['type'],
                        detail.get('oldValue', 'N/A'),  # Display Old Value if present
                        detail.get('newValue', 'N/A')  # Display New Value
                    )
                    tree.insert('', 'end', iid=index, text=str(index), values=values)
                    index += 1
    except Exception as e:
        print(f"Error populating 'Changed' table: {e}")



def populate_all_table(tree, data, filter_type='All'):
    """Based on the chosen filter, fill the 'All' table with all of the columns."""
    try:
        for item in tree.get_children():
            tree.delete(item)  # Clear existing items before repopulating
        index = 1
        for entry in data.get('cveChanges', []):
            change = entry.get('change', {})
            for detail in change.get('details', []):
                if filter_type == 'All' or detail.get('action') == filter_type:
                    values = (
                        change.get('cveId', 'N/A'),
                        change.get('eventName', 'N/A'),
                        change.get('cveChangeId', 'N/A'),
                        change.get('sourceIdentifier', 'N/A'),
                        change.get('created', 'N/A'),
                        detail.get('action', 'N/A'),
                        detail.get('type', 'N/A'),
                        detail.get('oldValue', 'N/A'),
                        detail.get('newValue', 'N/A')
                    )
                    tree.insert('', 'end', iid=index, text=str(index), values=values)
                    index += 1
    except Exception as e:
        print(f"Error populating 'All' table: {e}")



def display_summary_table(data):
    """Present the summary table."""
    try:
        summary_data = extract_summary_data(data)
        display_summary_gui(summary_data)
    except Exception as e:
        print(f"Error displaying summary table: {e}")



def filter_data(data, action):
    """Use the action ('Added' or 'Changed') to filter the data."""
    try:
        filtered_data = {'cveChanges': []}
        for entry in data.get('cveChanges', []):
            change = entry.get('change', {})
            filtered_details = [detail for detail in change.get('details', []) if detail.get('action') == action]
            if filtered_details:
                filtered_change = {'change': change.copy()}
                filtered_change['change']['details'] = filtered_details
                filtered_data['cveChanges'].append(filtered_change)
        return filtered_data
    except Exception as e:
        print(f"Error filtering data: {e}")
        return {'cveChanges': []}



def extract_summary_data(data):
    """
    Extract summary information using the chosen columns.
    Display GUI(s) of all “cveId”, “eventName”, “sourceIdentifier”, “created” 

    """
    try:
        summary_data = {'cveChanges': []}
        for entry in data.get('cveChanges', []):
            change = entry.get('change', {})
            summary_change = {
                'change': {
                    'cveId': change.get('cveId', 'N/A'),
                    'eventName': change.get('eventName', 'N/A'),
                    'cveChangeId': change.get('cveChangeId', 'N/A'),
                    'sourceIdentifier': change.get('sourceIdentifier', 'N/A'),
                    'created': change.get('created', 'N/A')
                }
            }
            summary_data['cveChanges'].append(summary_change)
        return summary_data
    except Exception as e:
        print(f"Error extracting summary data: {e}")
        return {'cveChanges': []}



def display_summary_gui(data):
    """Show a summary table in the GUI."""
    try:
        root = Tk()
        root.title("Summary Table")

        tree = ttk.Treeview(root, columns=('CVE ID', 'Event Name', 'Change ID', 'Source', 'Created'))
        tree.heading('#0', text='Index')
        tree.heading('CVE ID', text='CVE ID')
        tree.heading('Event Name', text='Event Name')
        tree.heading('Change ID', text='Change ID')
        tree.heading('Source', text='Source')
        tree.heading('Created', text='Created')

        tree.column('#0', stretch=NO, minwidth=0, width=50)
        tree.column('CVE ID', stretch=NO, minwidth=0, width=100)
        tree.column('Event Name', stretch=NO, minwidth=0, width=150)
        tree.column('Change ID', stretch=NO, minwidth=0, width=100)
        tree.column('Source', stretch=NO, minwidth=0, width=100)
        tree.column('Created', stretch=NO, minwidth=0, width=150)

        tree.pack(expand=YES, fill=BOTH)

        index = 1
        for entry in data.get('cveChanges', []):
            change = entry.get('change', {})
            tree.insert('', 'end', text=str(index), values=(
                change.get('cveId', 'N/A'),
                change.get('eventName', 'N/A'),
                change.get('cveChangeId', 'N/A'),
                change.get('sourceIdentifier', 'N/A'),
                change.get('created', 'N/A')
            ))
            index += 1

        root.mainloop()
    except Exception as e:
        print(f"Error displaying summary GUI: {e}")


def display_changed(data):
    """Display the 'Changed' entries in the UI window."""
    try:
        filtered_data = filter_data(data, action="Changed")
        display_gui(filtered_data, filter_type="Changed")
    except Exception as e:
        print(f"Error displaying 'Changed' entries: {e}")


def display_added(data):
    """Display the 'Added' entries in the UI pane."""
    try:
        filtered_data = filter_data(data, action="Added")
        display_gui(filtered_data, filter_type="Added")
    except Exception as e:
        print(f"Error displaying 'Added' entries: {e}")


def display_all_table(data):
    """Show the complete data table."""
    try:
        display_gui(data)
    except Exception as e:
        print(f"Error displaying all table: {e}")



def main():
    """Main function to plan the flow of data fetching, saving, parsing, and displaying."""
    if os.path.exists('cveCH_raw.json'):
        if messagebox.askyesno("Load Data", "Do you want to use the existing data?"):
            with open('cveCH_raw.json', 'r') as file:
                data = json.load(file)
        else:
            start_date, end_date = request_dates()
            data = fetch_data(start_date, end_date)
            save_json(data)
    else:
        start_date, end_date = request_dates()
        data = fetch_data(start_date, end_date)
        save_json(data)

    parse_to_csv(data)

    # Display the "View" window
    root = Tk()
    root.title("View")
    root.geometry("400x200")  # Set the initial size of the window

    all_button = Button(root, text="All Table", command=lambda: display_all_table(data))
    all_button.pack()

    added_button = Button(root, text="Added", command=lambda: display_added(data))
    added_button.pack()

    changed_button = Button(root, text="Changed", command=lambda: display_changed(data))
    changed_button.pack()

    summary_button = Button(root, text="Summary Table", command=lambda: display_summary_table(data))
    summary_button.pack()

    root.mainloop()


if __name__ == "__main__":
    main()
    # Main Call
