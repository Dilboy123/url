import pandas as pd
import joblib
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from flask import Flask, render_template, request

main = Flask(__name__)

# Load Url Data
urls_data = pd.read_csv("urldata.csv")


def makeTokens(f):
    tkns_BySlash = str(f.encode('utf-8')).split('/')  # make tokens after splitting by slash
    total_Tokens = []
    for i in tkns_BySlash:
        tokens = str(i).split('-')  # make tokens after splitting by dash
        tkns_ByDot = []
        for j in range(0, len(tokens)):
            temp_Tokens = str(tokens[j]).split('.')  # make tokens after splitting by dot
            tkns_ByDot = tkns_ByDot + temp_Tokens
        total_Tokens = total_Tokens + tokens + tkns_ByDot
    total_Tokens = list(set(total_Tokens))  # remove redundant tokens
    if 'com' in total_Tokens:
        total_Tokens.remove(
            'com')  # removing .com since it occurs a lot of times and it should not be included in our features
    return total_Tokens


# Get the URL
url_list = urls_data["url"]

# Using Custom Tokenizer
vectorizer = TfidfVectorizer(tokenizer=makeTokens, token_pattern=None)

vectorizer.fit_transform(url_list)

classifier = joblib.load("model_url.pkl")


#
# # list
# X_predict = []
#
# # counter
# counter = 0
#
# # Create a loop
# while counter < 3:
#     url = input(f"Enter the URL {counter+1}:")
#     X_predict.append(url)
#     counter += 1
#
# # Predict the data
# X_predict = vectorizer.transform(X_predict)
# New_predict = classifier.predict(X_predict)
#
# print(New_predict)

@main.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url_input']

        X_predict = vectorizer.transform([url])
        new_predict = classifier.predict(X_predict)

        check_url = f"https://www.virustotal.com/api/v3/domains/{url}"

        headers = {
            "accept": "application/json",
            "x-apikey": "f4e4c770c82857e1132d4f406a8ca29ad34f512e49e544e160461981515fc8fa"
        }

        response = requests.get(check_url, headers=headers)

        data = response.json()

        # Print a specific category item by key
        specific_category_key = "Forcepoint ThreatSeeker"
        specific_category_value = data['data']['attributes']['categories'].get(specific_category_key)

        return render_template('index.html', prediction=new_predict[0], input_url=url, category=specific_category_value)
    return render_template('index.html', prediction=None, input_url=None, category=None)


if __name__ == '__main__':
    main.run(debug=True)
    main.run(host='0.0.0.0', port=5000)
