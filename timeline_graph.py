#!/usr/bin/python3

import csv
import base64
from subprocess import Popen, PIPE, DEVNULL
import re
import sys
import argparse
import datetime
from concurrent.futures import ThreadPoolExecutor
import html
import io
import hashlib
import matplotlib.pyplot as plt

# Парсинг аргументов командной строки
parser = argparse.ArgumentParser(description="Скрипт для сбора временной шкалы файлов.")
parser.add_argument('-c', action='store_true', help='show changed files (slow)')
parser.add_argument('-f', type=argparse.FileType('w'), help='outfile for timeline')
parser.add_argument('-html', action='store_true', help='output timeline in HTML format')
parser.add_argument('-csv', action='store_true', help='output timeline in CSV format')
parser.add_argument('-u', type=str, help='filter by user')
parser.add_argument('-start-date', type=str, help='start date for filtering (DD.MM.YYYY)', required=False)
parser.add_argument('-end-date', type=str, help='end date for filtering (DD.MM.YYYY)', required=False)
parser.add_argument('-graph', action='store_true', help='visualize timeline with a graph')
parser.add_argument('-hash', type=str, choices=['md5', 'sha256'], help='choose hash type: md5 or sha256', required=False)
parser.add_argument('-exclude', nargs='+', help='directories to exclude from scanning', required=False)
parser.add_argument('-full', action='store_true', help='full scan with CSV output')

args = parser.parse_args()

# Если нет аргументов, выводим подсказку
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

# Функция для получения хэш-суммы файла
def get_file_hash(file_path, hash_algorithm='md5'):
    try:
        with open(file_path, 'rb') as f:
            if hash_algorithm == 'md5':
                hash_func = hashlib.md5()
            elif hash_algorithm == 'sha256':
                hash_func = hashlib.sha256()
            else:
                return None

            while chunk := f.read(8192):
                hash_func.update(chunk)
            return hash_func.hexdigest()
    except Exception:
        return None

# Функция для показа изменённых файлов
def show_changed_files():
    process = Popen(["dpkg", "--verify"], stdout=PIPE, stderr=PIPE)
    output, err = process.communicate()
    files = set(re.findall(r"/.*", output.decode('utf-8')))
    inaccessible = set(re.findall(r"unable to open (.*) for hash", err.decode("utf-8")))
    for fn in files - inaccessible:
        print(fn)

# Функция получения файлов, установленных пакетами
def get_package_files():
    process = Popen(["dpkg", "-S", "*"], stdout=PIPE, stderr=DEVNULL)
    output, _ = process.communicate()
    return set(re.findall(r"/.*", output.decode('utf-8')))

# Функция для сбора данных о временной шкале файловой системы
def get_timeline():
    exclude_args = []
    if args.exclude:
        for path in args.exclude:
            exclude_args += ['-not', '-path', f'{path}/*']

    process = Popen(["find", "/", "-xdev"] + exclude_args + ["-type", "f", "-printf", "%C@;%y%m;%u;%s;%p\n"], stdout=PIPE, stderr=PIPE)
    output, error_output = process.communicate()

    # Отладочный вывод ошибок от find
    if error_output:
        print("Errors from find command:", error_output.decode("utf-8"))

    result = output.decode("utf-8").split("\n")[:-1]
    if len(result) == 0:
        print("No data collected by find command.")
    else:
        print("First 10 entries from find command:", result[:10])

    return result

# Функция для форматирования размера файла
def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return "{:3.1f}{}{}".format(num, unit, suffix)
        num /= 1024.0
    return "{:.1f}Yi{}".format(num, suffix)

# Основная функция показа временной шкалы
def show_timeline():
    # Сбор данных
    timeline = get_timeline()

    print("Files cnt:", len(timeline))
    
    # Добавляем отладочный вывод первых 10 записей, чтобы понять, что вернул `find`
    if len(timeline) > 0:
        print("First 10 entries from find command:", timeline[:10])
    else:
        print("No entries found by find command.")

    # Преобразование временных рамок, если они заданы
    start_ts = int(datetime.datetime.strptime(args.start_date, '%d.%m.%Y').timestamp()) if args.start_date else None
    end_ts = int(datetime.datetime.strptime(args.end_date, '%d.%m.%Y').timestamp()) if args.end_date else None

    # Фильтрация данных по изменениям
    filtered_timeline = []
    for fl in timeline:
        data = fl.split(";")
        ts = int(data[0].split('.')[0])
        perm = data[1].lstrip('f')
        user = data[2]
        size = data[3]
        fname = ";".join(fl.split(";")[4:])
        
        # Фильтрация по пользователю
        if args.u and user != args.u:
            continue
        # Фильтрация по временным рамкам (если указана дата начала и/или конца)
        if start_ts and ts < start_ts:
            continue
        if end_ts and ts > end_ts:
            continue
        filtered_timeline.append((ts, user, perm, size, fname))

    print("Filtered timeline:", len(filtered_timeline))
    
    # Отладочный вывод первых 10 записей после фильтрации
    if len(filtered_timeline) > 0:
        print("First 10 filtered entries:", filtered_timeline[:10])
    else:
        print("No entries after filtering.")

    # Выбор метода вывода: HTML, CSV или граф
    if args.html:
        output_file = args.f.name if args.f else 'timeline_report.html'
        generate_html_report(filtered_timeline, output_file)
        print(f"HTML report saved to {output_file}")
    elif args.csv or args.full:
        output_file = args.f.name if args.f else 'timeline_report.csv'
        generate_csv_report(filtered_timeline, output_file)
        print(f"CSV report saved to {output_file}")
    elif args.graph:
        visualize_timeline(filtered_timeline)
    else:
        outfile = args.f if args.f else sys.stdout
        for line in sorted(filtered_timeline, reverse=True):
            ts, user, perm, size, fname = line
            size_fmt = sizeof_fmt(int(size))
            ctime = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            file_hash = get_file_hash(fname, args.hash) if args.hash else 'N/A'
            print("{:>8}\t{}\t{:>10}\t{:>20}\t{}\t{}".format(user, perm, size_fmt, ctime, fname, file_hash), file=outfile)

# Функция для генерации HTML отчета с графиком
def generate_html_report(timeline_data, output_file):
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Добавляем текущую дату на одной строке
    with open(output_file, 'w') as f:
        f.write(f'''
        <html><head><title>Forensic Timeline</title></head>
        <body><h1>Анализ выполнен {now}</h1>''')

        if args.graph:
            f.write("<h2>Timeline Graph</h2>")
            img_data = generate_timeline_graph(timeline_data)
            f.write(f'<img src="data:image/png;base64,{img_data}"/>')
        
        f.write('''
        <h1>Timeline</h1><table border="1">
        <tr><th>Пользователь</th><th>Права</th><th>Размер</th><th>Время изменения</th><th>Файл</th><th>Хэш</th></tr>
        ''')
        
        for entry in timeline_data:
            ts, user, perm, size, fname = entry
            size_fmt = sizeof_fmt(int(size))
            ctime = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            file_hash = get_file_hash(fname, args.hash) if args.hash else 'N/A'
            f.write(f"<tr><td>{html.escape(user)}</td><td>{html.escape(perm)}</td>"
                    f"<td>{html.escape(size_fmt)}</td><td>{html.escape(ctime)}</td><td>{html.escape(fname)}</td>"
                    f"<td>{html.escape(file_hash)}</td></tr>")
        
        f.write("</table></body></html>")

# Функция для генерации CSV отчета
def generate_csv_report(timeline_data, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Пользователь', 'Права', 'Размер', 'Время изменения', 'Файл', 'Хэш'])
        for entry in timeline_data:
            ts, user, perm, size, fname = entry
            size_fmt = sizeof_fmt(int(size))
            ctime = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            file_hash = get_file_hash(fname, args.hash) if args.hash else 'N/A'
            csvwriter.writerow([user, perm, size_fmt, ctime, fname, file_hash])

# Функция для визуализации временной шкалы
def visualize_timeline(timeline_data):
    if not timeline_data:
        print("No data to generate a graph.")
        return

    timestamps = [datetime.datetime.fromtimestamp(entry[0]) for entry in timeline_data]
    file_sizes = [int(entry[3]) for entry in timeline_data]

    plt.figure(figsize=(10, 6))
    plt.scatter(timestamps, file_sizes, c='blue', alpha=0.5)
    plt.title('File Modifications Timeline')
    plt.xlabel('Timestamp')
    plt.ylabel('File Size (bytes)')
    plt.xticks(rotation=45)
    plt.grid(True)

    plt.show()

# Функция для создания графика и кодирования его в base64
def generate_timeline_graph(timeline_data):
    timestamps = [datetime.datetime.fromtimestamp(entry[0]) for entry in timeline_data]
    file_sizes = [int(entry[3]) for entry in timeline_data]

    plt.figure(figsize=(10, 6))
    plt.scatter(timestamps, file_sizes, c='blue', alpha=0.5)
    plt.title('File Modifications Timeline')
    plt.xlabel('Timestamp')
    plt.ylabel('File Size (bytes)')
    plt.xticks(rotation=45)
    plt.grid(True)

    # Сохраняем график в буфер
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    img_data = base64.b64encode(buf.read()).decode('utf-8')
    return img_data

# Основная функция, обрабатывающая входные аргументы
def main():
    if args.c:
        show_changed_files()
    else:
        show_timeline()

if __name__ == "__main__":
    main()
