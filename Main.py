import os
import pandas as pd
import argparse
import pprint
import re
import sys
import textwrap
import bs4
import colored
import prettytable
import requests
from collections import defaultdict
from distutils.version import LooseVersion


#Generar listado de programas instalados Windows
os.system('wmic product get name,version /format:csv > InstalledSoftwareList.csv & wmic datafile where name="C:\\\Program Files (x86)\\\Mozilla Firefox\\\\firefox.exe" get name, version /format:csv >> InstalledSoftwareList.csv & wmic datafile where name="C:\\\Program Files\\\Mozilla Firefox\\\\firefox.exe" get name, version /format:csv >> InstalledSoftwareList.csv & wmic datafile where name="C:\\\Program Files (x86)\\\Google\\\Chrome\\\Application\\\chrome.exe" get name, version /format:csv >> InstalledSoftwareList.csv & wmic datafile where name="C:\\\Program Files\\\Internet Explorer\\\iexplore.exe" get name, version /format:csv >> InstalledSoftwareList.csv & cls')

results = 0
program_name = ""
installed_software = pd.read_csv('InstalledSoftwareList.csv', encoding = "utf-16", header=0)

###########################################################################################################################

def colores(string, color=None, highlight=None, attrs=None):
    return colored.stylize(
        string,
        (colored.fg(color) if color else "")
        + (colored.bg(highlight) if highlight else "")
        + (colored.attr(attrs) if attrs else ""),
    )

def tabla(columnas, datos, hrules=True):
    columnas = map(lambda x: colores(x, attrs="bold"), columnas)
    tabla = prettytable.PrettyTable(
        hrules=prettytable.ALL if hrules else prettytable.FRAME, field_names=columnas
    )
    for row in datos:
        tabla.add_row(row)
    tabla.align = "l"
    print(tabla)


def get_cvss_score(vuln, vulners_api):
    cvss = r["cvss"]["score"]

    if cvss == 0.0:
        return vulners_api.aiScore(vuln["description"])[0]
    else:
        return cvss


def color_cvss(cvss):
    cvss = float(cvss)
    if cvss < 3:
        color = "green_3b"
    elif cvss <= 5:
        color = "yellow_1"
    elif cvss <= 7:
        color = "orange_1"
    elif cvss <= 8.5:
        color = "dark_orange"
    else:
        color = "red"
    return color

def severidad_cvss(cvss):
    cvss = float(cvss)
    if cvss < 3:
        severidad = "Nula"
    elif cvss <= 5:
        severidad = "Baja"
    elif cvss <= 7:
        severidad = "Media"
    elif cvss <= 8.5:
        severidad = "Alta"
    else:
        severidad = "Critica"
    return severidad


def info(string):
    print(colores("[*] ", color="light_blue", attrs="bold") + string)


def warning(string):
    print(
        colores("[!] ", color="dark_orange", attrs="bold")
        + colores(string, color="dark_orange")
    )


def error(string):
    print(colores("[!] {}".format(string), color="red", attrs="bold"))


def success(string):
    print(colores("[+] {}".format(string), color="green_3b", attrs="bold"))


def get_closest_superior_version(target_version, list_avail_versions):
    sup_versions = list()
    for v in list_avail_versions:
        try:
            if LooseVersion(v) >= LooseVersion(target_version):
                sup_versions.append(LooseVersion(v))
        except:
            pass

    if sup_versions:
        return str(min(sup_versions))
    else:
        return None


def retrieve_id_from_link(href, type_id):
    id_search = re.search("/" + type_id + "/([0-9]+)/", href)
    if not id_search:
        return None
    return id_search.group(1)


def parse_html_table_versions(html):
    soup = bs4.BeautifulSoup(html, "html.parser")
    table_results = soup.find(class_="searchresults")
    versions_results = defaultdict(list)

    if not table_results:
        error(
            "Error: cvedetails no devuelve una tabla con las versiones disponibles. "
            "¡Probablemente hay un error en los detalles de cvedetails o la base de datos está caída!"
        )
        return

    for row in table_results.findAll("tr")[1:]:
        col = row.findAll("td")
        version = col[3].text.strip()

        version_id = retrieve_id_from_link(col[8].find("a")["href"], "version")
        if version_id:
            versions_results[version].append(version_id)

    return versions_results


def get_ids_from_cve_page(resp, vendor):
    soup = bs4.BeautifulSoup(resp, "html.parser")
    title_links = soup.find("h1").findAll("a")

    vendor = vendor or title_links[0].text
    vendor_id = retrieve_id_from_link(title_links[0]["href"], "vendor")
    if not vendor_id:
        error("Error: No se puede obtener la identificación del proveedor!")
        return

    product_id = retrieve_id_from_link(title_links[1]["href"], "product")
    if not product_id:
        error("Error: No se puede obtener la identificación del producto!")
        return

    version = title_links[2].text.strip()
    version_id = [retrieve_id_from_link(title_links[2]["href"], "version")]
    if not version_id:
        error("Error: No se puede obtener el ID de la versión!")
        return

    return vendor, vendor_id, product_id, version, version_id


def get_ids_from_searchresults(resp, vendor):
    soup = bs4.BeautifulSoup(resp, "html.parser")
    table_results = soup.find(class_="searchresults")

    row_1 = table_results.findAll("tr")[1]
    vendor_id = retrieve_id_from_link(row_1.findAll("td")[1].find("a")["href"], "vendor")
    if not vendor_id:
        error("Error: No se puede obtener la identificación del proveedor!")
        return
    vendor = vendor or row_1.findAll("td")[1].find("a").text

    product_id = retrieve_id_from_link(
        row_1.findAll("td")[2].find("a")["href"], "product"
    )
    if not product_id:
        error("Error: No se puede obtener la identificación del producto!")
        return

    return vendor, vendor_id, product_id


def request_search(vendor, product, version):
    r = requests.get(
        "https://www.cvedetails.com/version-search.php?"
        "vendor={vendor}&product={product}&version={version}".format(
            vendor=vendor, product=product, version=version
        ),
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0"},
    )

    if r.status_code != 200:
        error("Ocurrió un error HTTP. Codigo {} devuelto".format(r.status_code))
        return
    else:
        return r.text


def is_cve_in_json(cve_id, json):
    for cve in json:
        if cve["cve_id"] == cve_id:
            return True
    return False


def merge_jsons(jsons_list):
    results = list()
    for json in jsons_list:
        for cve in json:
            if not is_cve_in_json(cve["cve_id"], results):
                results.append(cve)
    return results

def generate_csv(archivo):
    csvdata = "ID;CVSS;Date;Description;URL;Exploit?\n"
    for r in results:
        csvdata += "{cve};{cvss};{date};{description};{url};{exploit}\n".format(
            cve=r["cve_id"],
            cvss=r["cvss_score"],
            date=r["publish_date"],
            description=r["summary"].replace(";", ","),
            url=r["url"],
            exploit="None" if r["exploit_count"] == "0" else r["exploit_count"],
        )

    try:
        os.stat(os.path.dirname(os.path.abspath(__file__))+"\\reportes\\")
    except Exception as e:
        os.mkdir(os.path.dirname(os.path.abspath(__file__))+"\\reportes\\")

    try:
        with open(os.path.dirname(os.path.abspath(__file__))+"\\reportes\\"+ archivo +".csv", "w") as f:
            f.write(csvdata)
        info("Para más detalle consulte el archivo '"+ archivo +".csv' en la carpeta reportes")
    except Exception as e:
        error("Se produjo un error al tratar de escribir el archivo CSV: {exc}".format(exc=e))


def busqueda(product, version):
    global program_name
    global results
    vendor = ""

    info(
        'Buscando para "{product} {version}" en cvedetails.com '.format(
            product=program_name,
            version=program_version,
        )
    )

    resp = request_search(vendor, program_name, program_version)

    if "List of cve security vulnerabilities related to this exact version" not in resp:
        version_found = False
        if "No matches" not in resp:
            versions_results = parse_html_table_versions(resp)

            if program_version in versions_results:
                version_id = versions_results[program_version]
                version = program_version
                success(
                    "Coincidencia exacta encontrada en la base de datos  (en {} entradas, "
                    "los resultados se uniran)".format(len(version_id))
                )
                vendor, vendor_id, product_id = get_ids_from_searchresults(resp, vendor)
                version_found = True

        if not version_found:
            warning(
                "No hay una coincidencia exacta para este producto/versión. "
                "Comprobando si hay CVE en las nuevas versiones..."
            )

            resp = request_search(vendor or "", program_name, "")

            if "No matches" in resp:
                error(
                    'El producto "{product}" no esta referenciado en '
                    "cvedetails.com !".format(
                        product=program_name,
                    )
                )
                return

            i = len(program_version)
            superior_version_found = False
            while i >= 0:
                version_search = program_version[:i] + "%"
                #info("Comprobando con la versión = {}".format(version_search))
                resp = request_search(vendor or "", program_name, version_search)

                if "Security Vulnerabilities" in resp:
                    vendor, vendor_id, product_id, version, version_id = get_ids_from_cve_page(
                        resp, vendor
                    )

                    try:
                        if LooseVersion(version) >= LooseVersion(program_version):
                            superior_version_found = True
                            break
                    except:
                        pass

                elif (
                    "No matches" not in resp
                    and "Could not find any vulnerabilities" not in resp
                ):
                    versions_results = parse_html_table_versions(resp)

                    version = get_closest_superior_version(
                        program_version, versions_results.keys()
                    )
                    version_id = versions_results[version]
                    vendor, vendor_id, product_id = get_ids_from_searchresults(resp, vendor)

                    if version:
                        superior_version_found = True
                        break
                i -= 1

            if not superior_version_found:
                error("No se ha encontrado una versión superior en la base de datos de cvedetails.com")
                info("No existen vulnerabilidades para este producto")
                return
            else:
                success("La versión superior más cercana que se encuentra en la base de datos es: {}".format(version))

    else:
        success("La coincidencia exacta encontrada en la base de datos")
        vendor, vendor_id, product_id, version, version_id = get_ids_from_cve_page(resp, vendor)

    info(
        "Resumen de IDs: Vendor={vendor} [{vendor_id}] | Product={product} "
        "[{product_id}] | Version={version} [{version_id}]".format(
            vendor=vendor,
            vendor_id=vendor_id,
            product=program_name,
            product_id=product_id,
            version=version,
            version_id=",".join(version_id),
        )
    )

    jsons_list = list()
    for v_id in version_id:
        info("Obtener los resultados de la versión --> ID: {} ...".format(v_id))
        r = requests.get(
            "http://www.cvedetails.com/json-feed.php?numrows=30&vendor_id={vendor_id}&"
            "product_id={product_id}&version_id={version_id}&hasexp=0&opec=0&opov=0&opcsrf=0&"
            "opfileinc=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&"
            "opginf=0&opdos=0&orderby=3&cvssscoremin=0".format(
                vendor_id=vendor_id, product_id=product_id, version_id=v_id
            ),
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0"},
        )

        if r.status_code != 200:
            error("Ocurrió un error HTTP. Codigo {} devuelto".format(r.status_code))
        else:
            jsons_list.append(r.json())

    if len(jsons_list) > 1:
        results = merge_jsons(jsons_list)
    elif len(jsons_list) == 1:
        results = jsons_list[0]
    else:
        error("No se ha obtenido ningún resultado !")
        return

    if len(results) > 0:
        sum = 0
        for i in results:
            sum+=float(i['cvss_score'])
        promedio = sum / float(len(results))
        success("Número total de CVEs que se han obtenido: {}".format(len(results)))
        print(colores("[+] Promedio de vulnerabilidades: " + str(promedio), color_cvss(promedio), attrs="bold"))
        print(colores("[+] Severidad de vulnerabilidades: " +severidad_cvss(promedio), color_cvss(promedio), attrs="bold"))
        generate_csv(program_name)
        
    else:
        warning("No se encontró ningún CVE en la base de datos")
        info("No existen vulnerabilidades para este producto")
        return

    columns = ["CVE", "CVSS", "Fecha", "Descripcion", "URL"]
    data = list()
    promedio = 0
    for r in results:
        data.append(
            [
                colores(r["cve_id"], attrs="bold"),
                colores(r["cvss_score"], color=color_cvss(r["cvss_score"]), attrs="bold"),
                r["publish_date"],
                textwrap.fill(r["summary"], 80),
                r["url"],
            ]
        )

    #info("Los resultados están ordenados por fecha de publicación (desc):")
    #tabla(columns, data, hrules=True)
    
###########################################################################################################################
cpe = pd.read_csv('CPE.csv', header=0)
cpe_list = cpe['Programs']

info("Iniciando escaneo...\n")
for i in cpe_list:
    program_name = i
    names = installed_software[installed_software['Name'].str.contains(i, na=False, case=False)]
    if not names.empty:
        info('Programa --> '+ program_name)
        program_version = names['Version'].iloc[0]
        info('Versión --> ' + program_version)
        busqueda(program_name, program_version)
        print()

info("Fin del escaneo")
os.system('pause')
