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
import matplotlib.pyplot as plt

# Парсинг аргументов командной строки
parser = argparse.ArgumentParser()
parser.add_argument('-c', action='store_true', help='show changed files (slow)')
parser.add_argument('-f', type=argparse.FileType('w'), help='outfile for timeline')
parser.add_argument('-html', action='store_true', help='output timeline in HTML format')
parser.add_argument('-csv', action='store_true', help='output timeline in CSV format')
parser.add_argument('-u', type=str, help='filter by user')
parser.add_argument('-start-date', type=str, help='start date for filtering (DD.MM.YYYY)', required=False)
parser.add_argument('-end-date', type=str, help='end date for filtering (DD.MM.YYYY)', required=False)
parser.add_argument('-graph', action='store_true', help='visualize timeline with a graph')
args = parser.parse_args()

# Функция для показа изменённых файлов
def show_changed_files():
    process = Popen(["dpkg", "--verify"], stdout=PIPE, stderr=PIPE)
    output, err = process.communicate()
    files = set(re.findall("/.*", output.decode('utf-8')))
    inaccessible = set(re.findall("unable to open (.*) for hash", err.decode("utf-8")))
    for fn in files - inaccessible:
        print(fn)

# Функция получения файлов, установленных пакетами
def get_package_files():
    process = Popen(["dpkg", "-S", "*"], stdout=PIPE, stderr=DEVNULL)
    output, _ = process.communicate()
    return set(re.findall("/.*", output.decode('utf-8')))

# Функция для сбора данных о временной шкале файловой системы
def get_timeline():
    process = Popen(["find", "/", "-type", "d,f", "-xdev", "-printf", "%C@;%y%m;%u;%s;%p\n"], stdout=PIPE, stderr=DEVNULL)
    output, _ = process.communicate()
    return output.decode("utf-8").split("\n")[:-1]

# Функция для форматирования размера файла
def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return "{:3.1f}{}{}".format(num, unit, suffix)
        num /= 1024.0
    return "{:.1f}Yi{}".format(num, suffix)

# Функция для преобразования даты в timestamp
def parse_date(date_str):
    return int(datetime.datetime.strptime(date_str, '%d.%m.%Y').timestamp())

# Основная функция показа временной шкалы
def show_timeline():
    # Многопоточный сбор данных
    with ThreadPoolExecutor() as executor:
        future_timeline = executor.submit(get_timeline)
        future_package_files = executor.submit(get_package_files)

        timeline = future_timeline.result()
        packageset = future_package_files.result()

    print("Files cnt: {}".format(len(timeline)))
    print("Files from repositories: {}".format(len(packageset)))

    # Преобразование временных рамок, если они заданы
    start_ts = parse_date(args.start_date) if args.start_date else None
    end_ts = parse_date(args.end_date) if args.end_date else None

    # Фильтрация данных по файлам, которые не являются частью пакетов
    filtered_timeline = []
    for fl in timeline:
        data = fl.split(";")
        ts = int(data[0].split('.')[0])
        perm = data[1]
        user = data[2]
        size = data[3]
        fname = ";".join(fl.split(";")[4:])
        if fname not in packageset:
            # Фильтрация по пользователю
            if args.u and user != args.u:
                continue
            # Фильтрация по временным рамкам
            if start_ts and ts < start_ts:
                continue
            if end_ts and ts > end_ts:
                continue
            filtered_timeline.append((ts, user, perm, size, fname))

    # Сортировка по дате и времени (от первой к последней)
    filtered_timeline = sorted(filtered_timeline, key=lambda x: x[0])

    print("Filtered timeline: {}".format(len(filtered_timeline)))

    # Выбор метода вывода: HTML, CSV или граф
    if args.html:
        output_file = args.f.name if args.f else 'timeline_report.html'
        generate_html_report(filtered_timeline, output_file, args.graph)
        print(f"HTML report saved to {output_file}")
    elif args.csv:
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
            print("{:>8}\t{}\t{:>10}\t{:>20}\t{}".format(user, perm, size_fmt, ctime, fname), file=outfile)

# Функция для генерации HTML отчета с графиком
def generate_html_report(timeline_data, output_file, include_graph=False):
    with open(output_file, 'w') as f:
        f.write('''
        <html><head><title>Forensic Timeline</title></head>
        <body><h1>Timeline Graph</h1>
        ''')
        
        # Если включен график, добавляем его сразу после заголовка
        if include_graph:
            f.write("<h2>Timeline Graph</h2>")
            img_data = generate_timeline_graph(timeline_data)
            f.write(f'<img src="data:image/png;base64,{img_data}"/>')
        
        # Далее добавляем таблицу
        f.write('''
        <h1>Timeline</h1><table border="1">
        <tr><th>Пользователь</th><th>Права</th><th>Размер</th><th>Время изменения</th><th>Файл</th></tr>
        ''')
        
        for entry in timeline_data:
            ts, user, perm, size, fname = entry
            size_fmt = sizeof_fmt(int(size))
            ctime = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"<tr><td>{html.escape(user)}</td><td>{html.escape(perm)}</td>"
                    f"<td>{html.escape(size_fmt)}</td><td>{html.escape(ctime)}</td><td>{html.escape(fname)}</td></tr>")
        
        f.write("</table></body></html>")

# Функция для генерации CSV отчета
def generate_csv_report(timeline_data, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Пользователь', 'Права', 'Размер', 'Время изменения', 'Файл'])
        for entry in timeline_data:
            ts, user, perm, size, fname = entry
            size_fmt = sizeof_fmt(int(size))
            ctime = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            csvwriter.writerow([user, perm, size_fmt, ctime, fname])

# Функция для визуализации временной шкалы
def visualize_timeline(timeline_data):
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
