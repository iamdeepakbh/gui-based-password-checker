import tkinter as tk
import re
import requests
import hashlib


def validate_min_len(min_len_str):
    # compiling regex to create regex object
    pattern = re.compile(r"\b([8-9]|[1-9][0-9]|1[0-9][0-9]|200)\b")
    return re.search(pattern, min_len_str)


def validate_password(password, min_len):
    # compiling regex to create regex object
    pattern = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\u0020-\u002F\u003A-\u0040\u005B-\u0060\u007B-\u007E])[A-Za-z\d\u0020-\u002F\u003A-\u0040\u005B-\u0060\u007B-\u007E]{" + str(
            min_len) + ",200}$")
    return re.search(pattern, password)


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


class MyGUI:

    def __init__(self):

        self.root = tk.Tk()
        self.root.geometry('640x400')
        self.root.title('Password Validator')

        self.password_frame = tk.Frame(self.root)
        self.password_frame.columnconfigure(0, weight=1)
        self.password_frame.columnconfigure(1, weight=1)

        self.label = tk.Label(self.password_frame, text='Type the password to validate....', font=(
            'Arial', 12)).grid(row=0, column=0)
        # self.label.pack(padx=10, pady=10)

        self.password_entry = tk.StringVar()
        self.passwordEntry = tk.Entry(
            self.password_frame, textvariable=self.password_entry, font=('Arial', 16), show='*').grid(row=0, column=1)
        # self.passwordEntry.pack(padx=10, pady=10)

        self.label = tk.Label(self.password_frame, text='Confirm the password to validate.', font=(
            'Arial', 12)).grid(row=1, column=0)
        # self.label.pack(padx=10, pady=10)

        self.password_confirm = tk.StringVar()
        self.passwordConfirm = tk.Entry(
            self.password_frame, textvariable=self.password_confirm, font=('Arial', 16), show='*').grid(row=1, column=1)
        self.password_frame.pack(padx=20, pady=20)

        self.check_frame = tk.Frame(
            self.root, highlightbackground="grey", highlightthickness=1)
        self.check_frame.columnconfigure(0, weight=1)
        self.check_frame.columnconfigure(1, weight=1)
        self.check_frame.columnconfigure(2, weight=1)
        self.check_frame.columnconfigure(3, weight=1)

        self.check_complexity_state = tk.IntVar()
        self.check_complexity = tk.Checkbutton(self.check_frame, text='Check Complexity', font=(
            'Arial', 12), variable=self.check_complexity_state).grid(row=0, column=0, sticky=tk.W + tk.E)
        # self.check_complexity.pack(padx=10, pady=10)

        self.check_pawned_state = tk.IntVar()
        self.check_pawned = tk.Checkbutton(self.check_frame, text='Check Pawned', font=(
            'Arial', 12), variable=self.check_pawned_state).grid(row=0, column=1, sticky=tk.W + tk.E)
        # self.check_pawned.pack(padx=10, pady=10)

        self.min_length_label = tk.Label(self.check_frame, text='        Minimum length', font=(
            'Arial', 12)).grid(row=0, column=2, sticky=tk.W + tk.E)

        self.minimum_length = tk.StringVar()
        self.minimum_length.set('8')
        self.minimumLength = tk.Entry(
            self.check_frame, textvariable=self.minimum_length, font=('Arial', 12), width=3).grid(row=0, column=3,
                                                                                                  sticky=tk.W + tk.E)

        self.check_frame.pack(padx=20, pady=20)

        self.button = tk.Button(
            self.root, text='Test the password', font=('Arial', 18), command=self.show_message)
        self.button.pack(padx=10, pady=10)

        self.answer = tk.Label(self.root, text='', font=('Arial', 12))
        self.answer.pack(padx=10, pady=10)

        self.answer2 = tk.Label(self.root, text='', font=('Arial', 12))
        self.answer2.pack(padx=10, pady=10)

        self.root.mainloop()

    def show_message(self):
        vml = count = 0
        self.answer.config(text='')
        self.answer2.config(text='')
        if validate_min_len(f"{self.minimum_length.get()}"):
            try:
                vml = abs(int(f"{self.minimum_length.get()}"))
            except ValueError:
                self.answer.config(
                    text='A rare case of logic. It should not arise. :o ')
                return
        else:
            self.answer.config(
                text='Minimum length is an integer between 8 and 200')
            return

        if not self.check_pawned_state.get() and not self.check_complexity_state.get():
            self.answer.config(
                text='Nothing to check!!')
            return

        if len(self.password_entry.get()) < vml:
            self.answer.config(
                text='The password provided is shorter than the Minimum Length!!')
            return

        if self.password_entry.get() == self.password_confirm.get():
            if self.check_complexity_state.get():
                if validate_password(self.password_entry.get(), vml):
                    self.answer.config(
                        text='The password provided MEETS the complexity condition.')
                else:
                    self.answer.config(
                        text='The password provided does NOT meet the complexity condition.')
            if self.check_pawned_state.get():
                count = pwned_api_check(self.password_entry.get())
                if count:
                    self.answer2.config(
                        text=f'The password provided was pawned {count} times... you should probably change it!')
                else:
                    self.answer2.config(text=f'The password provided was NOT pawned. Carry on!')
        else:
            self.answer.config(
                text='The provided password and the confirmation do not match.')

        return


if __name__ == '__main__':
    MyGUI()