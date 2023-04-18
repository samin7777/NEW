msg = (
    '------MENU-------                                           \n'
    "                                                            \n"
    "   1) PORT Scannner                                                 \n"
    "                                                                      \n"
    "   2) HoneyPot                                                             \n"
    "                                                                              \n"
    "   3) Exit                                                                   \n"

)


class bold_color:  # Change colours according to your need
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


print(bold_color.PURPLE)
print(msg)
if __name__ == "__main__":
    while True:
        menu = int(input("Choose      : "))
        if menu in range(1, 4):
            break
    if menu == 1:
        import scan

        scan.scanner()
    elif menu == 2:
        exec(open('Honeypot.py').read())
    elif menu == 3:
        quit()
