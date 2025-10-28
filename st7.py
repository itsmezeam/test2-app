import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.title("Data Dashboard")

uploadFile = st.file_uploader("Upload a CSV file.", type="csv")

if uploadFile is not None:
    st.write("File Uploaded...")
    df = pd.read_csv(uploadFile)

    st.subheader("Data Preview")
    st.write(df.head())

    st.subheader("Data Summary")
    st.write(df.describe())

    # st.subheader('Filter Data')
    # columns = df.columns.tolist()
    # selectedColumns = st.selectbox("Select column to filter by", columns)