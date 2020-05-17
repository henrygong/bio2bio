# https://www.tutorialspoint.com/flask/flask_sending_form_data_to_template.htm
from flask import Flask, render_template, request
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/post')
def post():
    return render_template('post.html')

@app.route('/postresult',methods = ['POST', 'GET'])
def postResult():
    if request.method == 'POST':
        result = request.form
        import sys, os.path
        postToEth_dir = \
            (os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        sys.path.append(postToEth_dir)
        import postToEth as pte
        myCL = pte.CommandLine()
        myCL.arguments['post'] = True
        myCL.arguments['previous'] = result['prevHash']
        myCL.arguments['file'] = result['file']
        myCL.arguments['folder'] = result['folder']
        myCL.arguments['account'] = result['account']
        myCL.arguments['privateKey'] = result['privateKey']
        myCL.arguments['doEncrypt'] = result['encrypt']
        myCL.arguments['password'] = result['password']

        from contextlib import redirect_stdout
        import io
        f = io.StringIO()
        with redirect_stdout(f):
            pte.main(myCL)
        myStdout = f.getvalue()

        return render_template("postResult.html",result = result, s=myStdout)

@app.route('/download')
def download():
    return render_template('download.html')

@app.route('/downloadresult',methods = ['POST', 'GET'])
def downloadResult():
    if request.method == 'POST':
        result = request.form
        import sys
        import os
        import ipfshttpclient
        client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')
        download_dir = result['folder']
        hash = result['hash'].replace(" ", "")
        hashes = hash.split(',')
        thisDir = os.getcwd()
        os.chdir(download_dir)
        for hash in hashes:
            res = client.get(hash)

        os.chdir(thisDir)
        return render_template("downloadResult.html",result = result)

@app.route('/query')
def query():
    return render_template('query.html')

@app.route('/result',methods = ['POST', 'GET'])
def result():
    if request.method == 'POST':
        result = request.form
        import sys, os.path
        postToEth_dir = \
            (os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        sys.path.append(postToEth_dir)
        import postToEth as pte
        myCL = pte.CommandLine()
        myCL.arguments['query'] = True

        hash = result['hash'].replace(" ", "")
        hashes = hash.split(',')
        stdouts = []
        collateds = []
        adjs = []
        from contextlib import redirect_stdout
        import io
        import pandas as pd
        for hash in hashes:
            myCL.arguments['hash'] = hash
            myCL.arguments['start'] = result['start']
            myCL.arguments['end'] = result['end']
            myCL.arguments['unencrypted'] = result['unencrypted']
            myCL.arguments['ext'] = "json"
            myCL.arguments['find'] = result['find']


            f = io.StringIO()
            with redirect_stdout(f):
                pte.main(myCL)
            myStdout = f.getvalue()
            import sys
            f.close()
            stdouts.append(myStdout)

            try:
                adjName = "adj_" + hash + ".csv"
                adj = pd.read_csv(adjName, index_col=0)
                adjs.append(adj.to_html())
            except pd.errors.EmptyDataError:
                adjs.append("No adjacency matrix.")

            dfName = "collatedJSONMetadata_" + hash + ".csv"
            collated = pd.read_csv(dfName, index_col=0)
            collateds.append(collated.to_html())

        return render_template("queryResult.html",
                               result = result, s=stdouts, a=adjs, c=collateds)

# https://www.rmedgar.com/blog/dynamic-fields-flask-wtf
# https://gist.github.com/rmed/def5069419134e9da0713797ccc2cb29

from flask_wtf import FlaskForm
from wtforms import Form, FieldList, FormField, IntegerField, StringField, \
        SubmitField
app.config['SECRET_KEY'] = 'mysecret'

class FieldForm(Form):
    """Subform.

    CSRF is disabled for this subform (using `Form` as parent class) because
    it is never used by itself.
    """
    field_name = StringField('Field name')
    field_data = StringField('Field data')

class MainForm(FlaskForm):
    """Parent form."""
    fields = FieldList(
        FormField(FieldForm),
        min_entries=1,
        max_entries=50
    )
    folder = StringField("Folder for metadata.json (required, use absolute path)")

@app.route('/json', methods=['GET', 'POST'])
def makejson():
    form = MainForm()
    return render_template('json.html', form=form)

@app.route('/jsonresult', methods=['GET', 'POST'])
def jsonResult():
    if request.method == 'POST':
        result = request.form.to_dict()
        folder = result['folder']
        import os
        thisDir = os.getcwd()
        os.chdir(folder)
        fieldNames = {}
        fieldData = {}
        for key, value in result.items():
            print(key, value)
            keySplit = key.split("-")
            if keySplit[0] == "fields":
                if keySplit[2] == "field_name":
                    fieldNames[keySplit[1]] = value
                elif keySplit[2] == "field_data":
                    fieldData[keySplit[1]] = value
        keyOrder = sorted(fieldNames)
        fieldNames = [fieldNames[key] for key in keyOrder]
        fieldData = [fieldData[key] for key in keyOrder]
        result = dict(zip(fieldNames, fieldData))
        import json
        with open('metadata.json', 'w') as f:
            json.dump(result, f)
        os.chdir(thisDir)
        return render_template('jsonResult.html', folder=folder, result=result)

if __name__ == '__main__':
   app.run(debug = True)
