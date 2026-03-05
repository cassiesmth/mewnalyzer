def coloring():
    # colors for output(for linux && macos)
    try:
        from colorama import init, Fore, Style
        init(autoreset=True)
        COLORS = True
    except ImportError:
        # colorama not installed
        class Fore:
            RED, GREEN, YELLOW, CYAN, MAGENTA, RESET = '', '', '', '', '', ''
        Style = Fore
        COLORS = False