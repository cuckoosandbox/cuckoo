# coding=utf-8
__author__ = 'm_messiah'
from pyminizip import compress
from requests import Session
from bs4 import BeautifulSoup


def sendKaspersky(filename, help_text, email, name):
    br = Session()
    hostUrl = "http://newvirus.kaspersky.com/"
    page = br.get(hostUrl)
    page = BeautifulSoup(page.text, 'html.parser')

    form = page.find('form', id="SendForm")

    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input') if 'name' in el])

    form_data["cc"] = "on"
    form_data["VirLabRecordModel.Email"] = email
    form_data["VirLabRecordModel.SuspiciousFilePath"] = name
    form_data["VirLabRecordModel.CategoryValue"] = "SuspiciousFile"

    response = br.post(hostUrl + form['action'], data=form_data,
                       files={'VirLabRecordModel.SuspiciousFileContent':
                              (name,open(filename, 'rb'))})

    if "was successfully sent" in response.text:
        return 0, "Success!"
    else:
        return 1, "Something goes wrong"


def sendDrWeb(filename, help_text, email, name):
    br = Session()
    page = br.get("https://vms.drweb.com/sendvirus/")
    page = BeautifulSoup(page.text, 'html.parser')
    form = page.find('form', id="SNForm")
    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input') if 'name' in el])

    form_data["email"] = email
    form_data["category"] = ["2"]
    form_data["text"] = help_text
    response = br.post(form['action'], data=form_data,
                       files={'file': (name, open(filename, 'rb'))})

    if "SNForm" not in response.text:
        return 0, "Success!"
    else:
        return 1, "Something goes wrong"


def sendEset(filename, help_text, email, name):
    if ".zip" not in filename:
        compress(filename, filename + ".zip", "infected", 5)
        filename += ".zip"
        name += ".zip"

    hostUrl = "http://www.esetnod32.ru/support/knowledge_base/new_virus/"
    br = Session()
    br.headers.update({'referer': hostUrl})

    page = br.get(hostUrl)
    page = BeautifulSoup(page.text, 'html.parser')

    form = page.find('form', id="new_license_activation_v")
    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input') if el.has_attr('name')])

    form_data["email"] = email
    del form_data["suspicious_file"]
    form_data["commentary"] = help_text

    response = br.post(hostUrl, data=form_data,
                       files={u'suspicious_file': (name,
                                                   open(filename, 'rb'),
                                                   "application/zip")})

    if u"Спасибо, Ваше сообщение успешно отправлено." in response.text:
        return 0, "Success!"
    else:
        return 1, "Something goes wrong"


def sendClamAV(filename, help_text, email, name):
    br = Session()
    hostUrl = "http://www.clamav.net"
    page = br.get(hostUrl + "/report/report-malware.html")
    page = BeautifulSoup(page.text, 'html.parser')

    credentials = br.get(hostUrl + "/presigned").json()
    submissionid = credentials.pop('id')

    form_s3 = page.find('form', id='s3Form')
    s3_url = form_s3['action']
    form_s3_data = dict([(el['name'], el.get('value', None))
                         for el in form_s3.find_all('input')])

    form_s3_data.update(credentials)

    s3_answer = br.post(s3_url, data=form_s3_data,
                        files={'file': (name, open(filename, 'rb'))})
    if s3_answer.status_code != 201:
        return 1, "Something wrong. s3 status = %s" % s3_answer.status_code

    form = page.find('form', id='fileData')
    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input')[:-1]])
    form_data['submissionID'] = submissionid
    form_data['sendername'] = email[:email.find("@")]
    form_data['email'] = email

    response = br.post(hostUrl + form['action'], data=form_data)

    if "Report Submitted" in response.text:
        return 0, "Success!"
    else:
        return 1, "Something goes wrong"


def sendMicrosoft(filename, help_text, email, name):
    br = Session()
    hostUrl = "https://www.microsoft.com/security/portal/submission/submit.aspx"
    br.headers.update({'referer': hostUrl})
    page = br.get(hostUrl)
    page = BeautifulSoup(page.text, 'html.parser')
    form = page.find('form', id='aspnetForm')

    form_data = dict([(el['name'], el.get('value', None))
                      for el in form.find_all('input') if el.has_attr('name')])

    form_data["ctl00$ctl00$pageContent$leftside$submitterName"] = email
    text = """I suspect this file contains malware <a
     href="#"
     onclick="window.open('../mmpc/shared/glossary.aspx#Malware',
     'Definitions', 'scrollbars=1,width=1000,height=500');"
     title="Click here for more details."
     >(?)</a>"""
    form_data["ctl00$ctl00$pageContent$leftside$incorrectDetectionRb"] = text
    form_data["ctl00$ctl00$pageContent$leftside$submissionComments"] = help_text
    form_data["ctl00$ctl00$pageContent$leftside$productSelection"] = [0]

    response = br.post(
        hostUrl, data=form_data,
        files={u'ctl00$ctl00$pageContent$leftside$submissionFile':
               (name, open(filename, 'rb'))})
    response_url = response.url

    response = BeautifulSoup(response.text, 'html.parser')
    answer = response.find(id="ctl00_ctl00_pageContent_contentTop_ctl00_"
                              "contenttop_submissionFileGrid_"
                              "ctl02_HyperlinkFileName")
    if answer:
        return 0, "Success! Your status is <a href='%s'>here (sha1=%s)</a>" % (response_url, answer['title'])
    else:
        return 1, "Something wrong"


ANTIVIRUSES = {
    "Kaspersky": sendKaspersky,
    "DrWeb": sendDrWeb,
    "ESET-NOD32": sendEset,
    "ClamAV": sendClamAV,
    "Microsoft": sendMicrosoft,
}
