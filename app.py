from flask import Flask, request, jsonify, render_template
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# Train the model when app starts
print("Training model...")
df = pd.read_csv("dataset.csv", header=None)

columns = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
'root_shell','su_attempted','num_root','num_file_creations','num_shells',
'num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count',
'srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
'label','difficulty']

df.columns = columns
df = df.drop('difficulty', axis=1)

le = LabelEncoder()
df['protocol_type'] = le.fit_transform(df['protocol_type'])
df['service'] = le.fit_transform(df['service'])
df['flag'] = le.fit_transform(df['flag'])
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

X = df.drop('label', axis=1)
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
model.fit(X)
print("Model ready.")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    
    input_data = pd.DataFrame([{
        'duration': data.get('duration', 0),
        'protocol_type': data.get('protocol_type', 1),
        'service': 0,
        'flag': data.get('flag', 9),
        'src_bytes': data.get('src_bytes', 0),
        'dst_bytes': data.get('dst_bytes', 0),
        'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
        'num_failed_logins': 0, 'logged_in': data.get('logged_in', 1),
        'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
        'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0,
        'is_host_login': 0, 'is_guest_login': 0,
        'count': 0, 'srv_count': 0, 'serror_rate': 0,
        'srv_serror_rate': 0, 'rerror_rate': 0, 'srv_rerror_rate': 0,
        'same_srv_rate': 0, 'diff_srv_rate': 0, 'srv_diff_host_rate': 0,
        'dst_host_count': 0, 'dst_host_srv_count': 0,
        'dst_host_same_srv_rate': 0, 'dst_host_diff_srv_rate': 0,
        'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0,
        'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
        'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
    }])

    prediction = model.predict(input_data)[0]
    score = model.decision_function(input_data)[0]

    if prediction == -1:
        return jsonify({
            'result': 'attack',
            'attack_type': 'ANOMALOUS NETWORK ACTIVITY',
            'score': round(abs(score), 4),
            'detectors': 87
        })
    else:
        return jsonify({
            'result': 'normal',
            'detectors': 12
        })

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
