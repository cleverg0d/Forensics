#!/usr/bin/python3

from subprocess import Popen, PIPE, DEVNULL
import re
import sys
import argparse
import datetime

IGNORED_PATTERNS = ["/usr/lib/modules", "/lib/modules", "/var/lib",
                    "/usr/share", "/usr/lib/python", "/boot", "/usr/lib/systemd", "/var/cache/",
                    "/usr/lib/udev", "/etc/alternatives", "/etc/ssl"]

parser = argparse.ArgumentParser()
parser.add_argument('-c', action='store_true', help='show changed files (slow)')
parser.add_argument('-f', type=argparse.FileType('w'), help='outfile for timeline')
args = parser.parse_args()


def show_changed_files():
    process = Popen(["dpkg", "--verify"], stdout=PIPE, stderr=PIPE)
    output, err = process.communicate()
    files = set(re.findall("/.*", output.decode('utf-8')))
    inaccessible = set(re.findall("unable to open (.*) for hash", err.decode("utf-8")))
    for fn in files - inaccessible:
        print(fn)


def get_package_files():
    process = Popen(["dpkg", "-S", "*"], stdout=PIPE, stderr=DEVNULL)
    output, err = process.communicate()
    return set(re.findall("/.*", output.decode('utf-8')))


def get_timeline():
    process = Popen(["find", "/", "-type", "d,f", "-xdev", "-printf", "%C@;%y%m;%u;%s;%p\n"], stdout=PIPE, stderr=DEVNULL)
    output, err = process.communicate()
    return output.decode("utf-8").split("\n")[:-1]  # last line is empty


def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return "{:3.1f}{}{}".format(num, unit, suffix)
        num /= 1024.0
    return "{:.1f}Yi{}".format(num, suffix)


def show_timeline():
    timeline = get_timeline()
    print("Files cnt: {}".format(len(timeline)))
    packageset = get_package_files()
    print("Files from repositories: {}".format(len(packageset)))
    filtered_timeline = []
    for fl in timeline:
        data = fl.split(";")
        ts = int(data[0].split('.')[0])
        perm = data[1]
        user = data[2]
        size = data[3]
        fname = ";".join(fl.split(";")[4:])
        if fname not in packageset and not any([fname.startswith(x) for x in IGNORED_PATTERNS]):
            filtered_timeline.append((ts, user, perm, size, fname))
    print("Filtered timeline: {}".format(len(filtered_timeline)))
    outfile = args.f if args.f else sys.stdout
    for line in sorted(filtered_timeline, reverse=True):
        ts, user, perm, size, fname = line
        size = sizeof_fmt(int(size))
        ctime = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        print("{:>8}\t{}\t{:>10}\t{:>20}\t{}".format(user, perm, size, ctime, fname), file=outfile)


def main():
    if args.c:
        print("Showing changed files")
        show_changed_files()
    else:
        print("Generating timeline")
        show_timeline()


if __name__ == "__main__":
    main()