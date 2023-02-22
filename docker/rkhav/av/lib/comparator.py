import difflib

TO_EXCLUDE = 'The system checks took'
MATCHES = ['[ Found ]', 'Warning']
NO_DIFF = "RKHunter didn't detect any system changes made by the malware\n"


def compare_report(file1, file2):
    file1_lines = file1.readlines()
    file2_lines = file2.readlines()

    file1_lines = [
        line for line in file1_lines if TO_EXCLUDE not in line]

    file2_lines = [
        line for line in file2_lines if TO_EXCLUDE not in line]

    difference = list(difflib.context_diff(file1_lines, file2_lines, n=0))[3:]

    if len(difference) != 0:
        difference = [line for line in difference if any(
            [x in line for x in MATCHES])]
        difference = ''.join(difference)
    else:
        difference = NO_DIFF

    return difference
