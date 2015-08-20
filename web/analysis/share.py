# coding=utf-8
__author__ = 'm_messiah'
from mechanize import Browser
from pyminizip import compress
from requests import Session
from bs4 import BeautifulSoup


def sendKaspersky(filename, help_text, email, sha):
    br = Browser()
    br.open("http://newvirus.kaspersky.com/")
    br.select_form(nr=0)
    br.form.add_file(open(filename),
                     "application/octetstream",
                     sha)
    br.form.set_all_readonly(False)
    br.form["VirLabRecordModel.Email"] = email
    br.form["VirLabRecordModel.SuspiciousFilePath"] = sha
    br.form["VirLabRecordModel.CategoryValue"] = "SuspiciousFile"
    response = br.submit()
    response = response.read()

    if "was successfully sent" in response:
        return 1, "Success!"
    else:
        return 0, "Something goes wrong"


def sendDrWeb(filename, help_text, email, sha):
    br = Browser()
    br.open("https://vms.drweb.com/sendvirus/")
    br.select_form(nr=1)
    br.form.add_file(open(filename),
                     "application/octetstream",
                     sha)
    br.form.set_all_readonly(False)
    br.form["category"] = ["2"]
    br.form["email"] = email
    br.form["text"] = help_text
    response = br.submit()
    response = response.read()

    if "SNForm" not in response:
        return 1, "Success!"
    else:
        return 0, "Something goes wrong"


def sendEset(filename, help_text, email, sha):
    if ".zip" not in filename:
        compress(filename, filename + ".zip", "infected", 5)
        filename += ".zip"

    br = Browser()
    br.open(
        "http://www.esetnod32.ru/support/knowledge_base/new_virus/")
    br.select_form(
        predicate=lambda f:
        f.attrs.get('id', None) == 'new_license_activation_v')
    br.form.set_all_readonly(False)
    br.form.add_file(open(filename), 'application/zip',
                     sha + ".zip")
    br.form["email"] = email
    br.form["commentary"] = help_text
    response = br.submit()
    response = response.read().decode("cp1251")
    if u"Спасибо, Ваше сообщение успешно отправлено." in response:
        return 1, "Success!"
    else:
        return 0, "Something goes wrong"


def sendClamAV(filename, help_text, email, sha):
    br = Session()
    hostUrl = "http://www.clamav.net"
    page = br.get(hostUrl + "/report/report-malware.html")
    page = BeautifulSoup(page.text, 'html.parser')

    credentials = br.get("http://www.clamav.net/presigned").json()
    submissionid = credentials['id']

    form_s3 = page.find('form', id='s3Form')
    s3_url = form_s3['action']
    form_s3_data = dict([(el['name'], el.get('value', None))
                         for el in form_s3.find_all('input')])

    form_s3_data.update(credentials)

    s3_answer = br.post(s3_url, data=form_s3_data,
                        files={'file': open(filename, 'rb')})
    if s3_answer.status_code != 201:
        return 0, "Something wrong. s3 status = %s" % s3_answer.status_code

    form = page.find('form', id='fileData')
    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input')[:-1]])
    form_data['submissionID'] = submissionid
    form_data['sendername'] = "Maxim"
    form_data['email'] = 'mmr@kontur.ru'

    response = br.post(hostUrl + form['action'], data=form_data)

    if "Report Submitted" in response.text:
        return 0, "Success!"
    else:
        return 1, "Something goes wrong"


ANTIVIRUSES = {
    "Kaspersky": sendKaspersky,
    "DrWeb": sendDrWeb,
    "ESET-NOD32": sendEset,
    "ClamAV": sendClamAV,
}