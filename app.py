import streamlit as st
import pickle
import pandas as pd
import google.generativeai as genai
from tensorflow.keras.models import load_model # type: ignore
import numpy as np
import struct

genai.configure(api_key="AIzaSyArFsF8XTEyuPDbQhtvGjZfygziLN6RF7o")

generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 64,
    "max_output_tokens": 1024,
    "response_mime_type": "text/plain",
}

gen_model = genai.GenerativeModel(
    model_name="gemini-1.5-flash",

    generation_config=generation_config,
)

@st.cache_resource
def load_models():
    cnn = load_model('models/cnn.h5')
    with open('models/xgb.pkl','rb') as f:
        xgb = pickle.load(f) 
    with open('models/dt.pkl','rb') as f:
        dt = pickle.load(f) 
    with open('models/encoder.pkl','rb') as f:
        encoder = pickle.load(f) 
    return {"encoder":encoder,"cnn":cnn,"xgb":xgb,"dt":dt}

def get_payload_length(payload):
    try:
        payload_clean = ''.join(c for c in payload if c in '0123456789ABCDEFabcdef')
        if not payload_clean:
            return 0
        byte_data = bytes.fromhex(payload_clean)
        return len(byte_data)
    except Exception:
        return 0
    
def process_df(df, encoder):
    df = df[relevant_columns]
    df['tcp.checksum'] = df['tcp.checksum'].apply(lambda x: int(x, 16))
    df['payload_length'] = df['tcp.payload'].apply(get_payload_length)
    df.drop('tcp.payload', axis=1,  inplace=True)
    df['mqtt.clientid'] = df['mqtt.clientid'].astype(str)
    df['mqtt.topic'] = df['mqtt.topic'].astype(str)
    df_encoded = df.copy()
    df_encoded[df_encoded.columns] = encoder.transform(df_encoded)
    df_reshaped = df_encoded.values.reshape(df_encoded.shape[0], df_encoded.shape[1], 1)
    return  df_encoded, df_reshaped

relevant_columns = [
    'tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.ack', 'tcp.window_size_value',
    'tcp.connection.fin', 'tcp.connection.syn', 'tcp.connection.rst', 'tcp.payload',
    'ip.src', 'ip.dst', 'ip.proto', 'ip.ttl', 'mqtt.clientid', 'mqtt.msgtype',
    'mqtt.topic', 'mqtt.kalive', 'mqtt.len', 'mqtt.qos', 'tcp.checksum',
    'tcp.hdr_len', 'frame.time_delta', 'frame.time_relative', 'tcp.time_delta'
]

def main():

    st.title("Cyber Attack Prediction In HealthCare")
    st.sidebar.markdown('''
### Cyber Attacks in Healthcare: IoT-Based ICU Use Case

#### Introduction

Cybersecurity is a growing concern in healthcare, particularly with the rise of IoT devices. These devices, such as patient monitors and sensors, collect and transmit critical health data, making them vulnerable to attacks. In healthcare settings like ICUs, any disruption to these devices could directly impact patient safety and care.

#### IoT Healthcare Use Case: 2-Bed ICU

In this scenario, we have a **2-bed ICU** setup where each bed is equipped with:

- **Nine patient monitoring sensors** (measuring vital signs like heart rate, blood pressure, temperature, etc.)
- **One central control unit**, called the **Bedx-Control-Unit**, which processes and aggregates data from the sensors.

These devices are connected in an IoT network to continuously monitor and transmit patient health data to medical staff.

#### Dataset Overview: Normal vs. Malicious Traffic

The dataset you're working with contains **normal** and **malicious** traffic patterns from the IoT-based ICU system. The goal is to classify whether the traffic is **normal** or indicative of a **cyberattack**.

- **Normal Traffic**: Represents standard communication between the sensors and the Bedx-Control-Unit, including the transmission of patient data and system status updates.
  
- **Malicious Traffic**: Represents abnormal traffic that deviates from the normal patterns, such as unauthorized or suspicious data exchanges, which could signal a security breach.

#### Key Points for Classification

- **Normal Traffic**: Typically involves the regular transmission of health data, status checks, and monitoring commands.
- **Malicious Traffic**: Involves irregular data patterns that could indicate an attempt to manipulate the system or compromise the integrity of the data.

By analyzing this dataset, machine learning models can be trained to accurately classify whether incoming traffic is **normal** or **malicious** based on features like packet size, frequency, and transmission patterns.

#### Conclusion

The use of IoT devices in healthcare provides numerous benefits but also introduces security risks. By classifying traffic as normal or malicious, healthcare organizations can proactively detect potential threats and ensure the safety and integrity of patient data and care systems.
    ''')
    csv_file = st.file_uploader("Upload your packet data", type=['csv']) 
    #st.write(struct.calcsize("P")* 8)   

    if st.button("Predict"):
        if csv_file:
            models = load_models()
            df = pd.read_csv(csv_file)
            df1, cnn_df = process_df(df, models['encoder'])
            xgb_pred = models['xgb'].predict(df1)
            dt_pred = models['dt'].predict(df1)
            cnn_pred = models['cnn'].predict(cnn_df)
            combined_preds = np.array([xgb_pred.astype(int), cnn_pred[:,0].astype(int), dt_pred.astype(int)])
            final_preds = np.apply_along_axis(lambda x: np.bincount(x).argmax(), axis=0, arr=combined_preds)
            st.write("Prediction:")
            if final_preds==1:
                st.error("Cyber Attack Detected")
                prompt = f'''You are a Network Security expert with specialisation in Health Care Networks. Our model has predicted that there is a Cyber Attack. Use the given params about the packet to give a detailed diagnosis in a report format. Packet Details:\n\n{df}\n\nDont keep any name or id in the report. Following columns were considered relevant by the model:\n\n{relevant_columns}'''
            else:
                st.success("No Cyber Attack Detected")
                prompt = f'''You are a Network Security expert with specialisation in Health Care Networks. Our model has predicted that there is no Cyber Attack. Use the given params about the packet to give a detailed diagnosis in a report format. Packet Details:\n\n{df}\n\nDont keep any name or id in the report. Following columns were considered relevant by the model:\n\n{relevant_columns}'''

            response = gen_model.generate_content(prompt)
            st.subheader("Diagnostic Report")
            st.markdown(response.text)
        

if __name__ == "__main__":
    main()

# # import streamlit as st
# # import pickle
# # import pandas as pd
# # import google.generativeai as genai
# # fro
# import streamlit as st
# import pickle
# import pandas as pd
# import google.generativeai as genai
# from tensorflow.keras.models import load_model
# import numpy as np

# # --- Configure AI ---
# genai.configure(api_key="AIzaSyArFsF8XTEyuPDbQhtvGjZfygziLN6RF7o")

# generation_config = {
#     "temperature": 1,
#     "top_p": 0.95,
#     "top_k": 64,
#     "max_output_tokens": 1024,
#     "response_mime_type": "text/plain",
# }

# gen_model = genai.GenerativeModel(
#     model_name="gemini-1.5-flash",
#     generation_config=generation_config,
# )

# # --- QuantumShield Cyberpunk UI ---
# quantum_style = """
# <style>
#     @import url('https://fonts.googleapis.com/css2?family=Electrolize&display=swap');

#     body {
#         font-family: 'Electrolize', sans-serif;
#         background: url('https://www.compucom.com/wp-content/uploads/2023/04/Compucom-Blog-Healthcare-Cybersecurity.png') no-repeat center fixed;
#         background-size: cover;
#         color: #ffffff;
#     }

#     .title {
#         color: #11ffcc;
#         text-align: center;
#         font-size: 3rem;
#         font-weight: bold;
#         text-shadow: 0px 0px 15px #11ffcc;
#     }

#     .stApp {
#         background: transparent !important;
#     }

#     .glass-container {
#         background: rgba(255, 255, 255, 0.08);
#         backdrop-filter: blur(15px);
#         padding: 20px;
#         border-radius: 15px;
#         box-shadow: 0px 0px 10px rgba(255, 255, 255, 0.2);
#     }

#     .stButton>button {
#         background: rgba(17, 255, 204, 0.2);
#         color: white;
#         padding: 12px;
#         border-radius: 12px;
#         font-size: 18px;
#         font-weight: bold;
#         transition: 0.3s;
#         border: 1px solid #11ffcc;
#     }

#     .stButton>button:hover {
#         background: rgba(17, 255, 204, 0.4);
#         transform: scale(1.05);
#     }

#     .upload-box {
#         border: 2px solid rgba(17, 255, 204, 0.6);
#         padding: 15px;
#         border-radius: 12px;
#         text-align: center;
#         background: rgba(0, 0, 0, 0.4);
#         font-size: 18px;
#         font-weight: bold;
#         color: #11ffcc;
#     }

#     .status-box {
#         padding: 15px;
#         border-radius: 12px;
#         text-align: center;
#         font-weight: bold;
#         font-size: 20px;
#         margin-top: 12px;
#     }

#     .alert-danger {
#         background: rgba(255, 0, 0, 0.2);
#         color: #ff4444;
#         box-shadow: 0px 0px 10px red;
#         border: 2px solid red;
#     }

#     .alert-success {
#         background: rgba(0, 255, 0, 0.2);
#         color: #00ff00;
#         box-shadow: 0px 0px 10px #00ff00;
#         border: 2px solid #00ff00;
#     }
# </style>
# """

# st.markdown(quantum_style, unsafe_allow_html=True)

# # --- Load AI Models ---
# @st.cache_resource
# def load_models():
#     with st.spinner("🚀 Initializing AI Models..."):
#         cnn = load_model('models/cnn.h5')
#         with open('models/xgb.pkl', 'rb') as f:
#             xgb = pickle.load(f)
#         with open('models/dt.pkl', 'rb') as f:
#             dt = pickle.load(f)
#         with open('models/encoder.pkl', 'rb') as f:
#             encoder = pickle.load(f)
#         return {"encoder": encoder, "cnn": cnn, "xgb": xgb, "dt": dt}

# # --- QuantumShield Cyber Dashboard ---
# st.markdown('<h1 class="title">🛡️ QuantumShield - AI Cybersecurity Threat Detection</h1>', unsafe_allow_html=True)

# # Upload Section
# st.markdown('<div class="upload-box">📂 Upload Network Packet Data (CSV)</div>', unsafe_allow_html=True)
# csv_file = st.file_uploader("", type=['csv'])

# # --- Predict Cyber Threats ---
# if st.button("🚀 Analyze Traffic Data"):
#     if csv_file:
#         st.info("🔄 Processing file...")

#         models = load_models()
#         df = pd.read_csv(csv_file)
#         df1 = df.copy()

#         # Predict using AI Models
#         xgb_pred = models['xgb'].predict(df1)
#         dt_pred = models['dt'].predict(df1)
#         cnn_pred = models['cnn'].predict(df1.values.reshape(df1.shape[0], df1.shape[1], 1))

#         combined_preds = np.array([xgb_pred.astype(int), cnn_pred[:, 0].astype(int), dt_pred.astype(int)])
#         final_preds = np.apply_along_axis(lambda x: np.bincount(x).argmax(), axis=0, arr=combined_preds)

#         # Display Results
#         if final_preds == 1:
#             st.markdown('<div class="status-box alert-danger">🚨 Cyber Attack Detected!</div>', unsafe_allow_html=True)
#         else:
#             st.markdown('<div class="status-box alert-success">✅ No Cyber Attack Detected!</div>', unsafe_allow_html=True)

# # --- AI Report Generation ---
# st.markdown("### 📊 AI-Generated Cybersecurity Report")
# if st.button("📄 Generate Report"):
#     with st.spinner("📝 Creating AI Report..."):
#         response = gen_model.generate_content("Generate a cybersecurity attack analysis report based on detected threats.")

#     st.subheader("📄 **Cybersecurity Report**")
#     st.markdown(f'<div class="glass-container">{response.text}</div>', unsafe_allow_html=True)

# # --- Footer ---
# st.markdown("<hr>", unsafe_allow_html=True)
# st.markdown("💡 **Developed by:** Your Name | 🚀 **Cybersecurity & AI Specialist**", unsafe_allow_html=True)


# # import streamlit as st
# # import pickle
# # import pandas as pd
# # import google.generativeai as genai
# # from tensorflow.keras.models import load_model
# # import numpy as np

# # # --- Configure AI ---
# # genai.configure(api_key="AIzaSyArFsF8XTEyuPDbQhtvGjZfygziLN6RF7o")

# # generation_config = {
# #     "temperature": 1,
# #     "top_p": 0.95,
# #     "top_k": 64,
# #     "max_output_tokens": 1024,
# #     "response_mime_type": "text/plain",
# # }

# # gen_model = genai.GenerativeModel(
# #     model_name="gemini-1.5-flash",
# #     generation_config=generation_config,
# # )

# # # --- QuantumShield UI Styling ---
# # quantum_style = """
# # <style>
# #     @import url('https://fonts.googleapis.com/css2?family=Electrolize&display=swap');
    
# #     body {
# #         font-family: 'Electrolize', sans-serif;
# #         background: url('https://www.healthcareperspectivesblog.com/wp-content/uploads/sites/855/2023/01/AdobeStock_495139916-scaled.jpeg') no-repeat center fixed;
# #         background-size: cover;
# #         color: #ffffff;
# #     }

# #     .title {
# #         color: #11ffcc;
# #         text-align: center;
# #         font-size: 3rem;
# #         font-weight: bold;
# #         text-shadow: 0px 0px 25px #11ffcc;
# #     }

# #     .stApp {
# #         background: rgba(10, 10, 10, 0.8);
# #         backdrop-filter: blur(10px);
# #         padding: 20px;
# #         border-radius: 15px;
# #         box-shadow: 0px 0px 20px #11ffcc;
# #     }

# #     .stButton>button {
# #         background: linear-gradient(45deg, #0044ff, #11ffcc);
# #         color: white;
# #         padding: 16px;
# #         border-radius: 12px;
# #         font-size: 18px;
# #         font-weight: bold;
# #         transition: 0.3s;
# #         border: none;
# #     }

# #     .stButton>button:hover {
# #         background: linear-gradient(45deg, #11ffcc, #0044ff);
# #         transform: scale(1.08);
# #     }

# #     .upload-box {
# #         border: 3px dashed #11ffcc;
# #         padding: 20px;
# #         border-radius: 15px;
# #         text-align: center;
# #         background: rgba(0, 0, 0, 0.6);
# #         font-size: 18px;
# #         font-weight: bold;
# #     }

# #     .status-box {
# #         padding: 18px;
# #         border-radius: 12px;
# #         text-align: center;
# #         font-weight: bold;
# #         font-size: 20px;
# #         margin-top: 12px;
# #     }

# #     .alert-danger {
# #         background: rgba(255, 0, 0, 0.2);
# #         color: #ff4444;
# #         box-shadow: 0px 0px 15px red;
# #         border: 2px solid red;
# #     }

# #     .alert-success {
# #         background: rgba(0, 255, 0, 0.2);
# #         color: #00ff00;
# #         box-shadow: 0px 0px 15px #00ff00;
# #         border: 2px solid #00ff00;
# #     }

# #     .glass-container {
# #         background: rgba(255, 255, 255, 0.1);
# #         backdrop-filter: blur(25px);
# #         padding: 20px;
# #         border-radius: 12px;
# #         box-shadow: 0px 0px 20px rgba(255, 255, 255, 0.2);
# #     }
# # </style>
# # """

# # st.markdown(quantum_style, unsafe_allow_html=True)

# # # --- Load Models ---
# # @st.cache_resource
# # def load_models():
# #     with st.spinner("🚀 Initializing AI Models..."):
# #         cnn = load_model('models/cnn.h5')
# #         with open('models/xgb.pkl', 'rb') as f:
# #             xgb = pickle.load(f)
# #         with open('models/dt.pkl', 'rb') as f:
# #             dt = pickle.load(f)
# #         with open('models/encoder.pkl', 'rb') as f:
# #             encoder = pickle.load(f)
# #         return {"encoder": encoder, "cnn": cnn, "xgb": xgb, "dt": dt}

# # # --- QuantumShield Cyber Dashboard ---
# # st.image("https://source.unsplash.com/1600x400/?cyber,security,ai,technology", use_column_width=True)
# # st.markdown('<h1 class="title">🛡️ QuantumShield - AI Cybersecurity Threat Detection</h1>', unsafe_allow_html=True)

# # # Upload Section
# # st.markdown('<div class="upload-box">📂 Upload Network Packet Data (CSV)</div>', unsafe_allow_html=True)
# # csv_file = st.file_uploader("", type=['csv'])

# # # --- Predict Cyber Threats ---
# # if st.button("🚀 Analyze Traffic Data"):
# #     if csv_file:
# #         st.info("🔄 Processing file...")

# #         models = load_models()
# #         df = pd.read_csv(csv_file)
# #         df1 = df.copy()

# #         # Predict using AI Models
# #         xgb_pred = models['xgb'].predict(df1)
# #         dt_pred = models['dt'].predict(df1)
# #         cnn_pred = models['cnn'].predict(df1.values.reshape(df1.shape[0], df1.shape[1], 1))

# #         combined_preds = np.array([xgb_pred.astype(int), cnn_pred[:, 0].astype(int), dt_pred.astype(int)])
# #         final_preds = np.apply_along_axis(lambda x: np.bincount(x).argmax(), axis=0, arr=combined_preds)

# #         # Display Results
# #         if final_preds == 1:
# #             st.markdown('<div class="status-box alert-danger">🚨 Cyber Attack Detected!</div>', unsafe_allow_html=True)
# #         else:
# #             st.markdown('<div class="status-box alert-success">✅ No Cyber Attack Detected!</div>', unsafe_allow_html=True)

# # # --- AI Report Generation ---
# # st.markdown("### 📊 AI-Generated Cybersecurity Report")
# # if st.button("📄 Generate Report"):
# #     with st.spinner("📝 Creating AI Report..."):
# #         response = gen_model.generate_content("Generate a cybersecurity attack analysis report based on detected threats.")

# #     st.subheader("📄 **Cybersecurity Report**")
# #     st.markdown(f'<div class="glass-container">{response.text}</div>', unsafe_allow_html=True)

# # # --- Footer ---
# # st.markdown("<hr>", unsafe_allow_html=True)
# # st.markdown("💡 **Developed by:** Your Name | 🚀 **Cybersecurity & AI Specialist**", unsafe_allow_html=True)

