import streamlit as st
import pandas as pd
import yfinance as yf
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import bcrypt
import boto3
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, FloatField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp, NumberRange

# AWS setup
s3 = boto3.client('s3')
lambda_client = boto3.client('lambda')

# Database setup
Base = declarative_base()
engine = create_engine('sqlite:///investment_management.db')
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    portfolio = relationship("Portfolio", back_populates="user")
    loans = relationship("Loan", back_populates="user")

class Portfolio(Base):
    __tablename__ = 'portfolios'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    stock_symbol = Column(String, nullable=False)
    investment_amount = Column(Integer, nullable=False)
    user = relationship("User", back_populates="portfolio")

class Loan(Base):
    __tablename__ = 'loans'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    loan_amount = Column(Integer, nullable=False)
    interest_rate = Column(Float, nullable=False)
    loan_term = Column(Integer, nullable=False)  # in months
    loan_status = Column(String, default='Pending')  # e.g., Pending, Approved, Rejected
    user = relationship("User", back_populates="loans")

# Password hash and verification functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))

# S3 file upload
def upload_to_s3(file_name, bucket, object_name=None):
    if object_name is None:
        object_name = file_name
    try:
        s3.upload_file(file_name, bucket, object_name)
    except Exception as e:
        print(f"Error uploading file: {e}")

# Lambda invocation example
def invoke_lambda(function_name, payload):
    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType='RequestResponse',
        Payload=json.dumps(payload)
    )
    return json.loads(response['Payload'].read())

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20),
        Regexp('^[a-zA-Z0-9]*$', message='Username must be alphanumeric')
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp('(?=.*[A-Z])', message='Password must contain an uppercase letter'),
        Regexp('(?=.*[a-z])', message='Password must contain a lowercase letter'),
        Regexp('(?=.*\\d)', message='Password must contain a digit'),
        Regexp('(?=.*[@$!%*?&])', message='Password must contain a special character')
    ])

class InvestmentForm(FlaskForm):
    stock_symbol = StringField('Stock Symbol', validators=[DataRequired()])
    investment_amount = IntegerField('Investment Amount', validators=[DataRequired(), NumberRange(min=1)])

class LoanForm(FlaskForm):
    loan_amount = IntegerField('Loan Amount', validators=[DataRequired(), NumberRange(min=1)])
    interest_rate = FloatField('Interest Rate', validators=[DataRequired(), NumberRange(min=0.01)])
    loan_term = IntegerField('Loan Term (months)', validators=[DataRequired(), NumberRange(min=1)])
    purpose = TextAreaField('Purpose', validators=[DataRequired(), Length(min=10, max=200)])

# Main application logic
def main():
    st.title("Investment and Lending Management System")
    page = st.session_state.get('page', 'signup')

    if page == 'signup':
        with st.form("signup_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Signup")

            if submit:
                hashed_password = hash_password(password)
                user = User(username=username, password=hashed_password.decode('utf-8'))
                session.add(user)
                session.commit()
                st.success("You have successfully signed up! Please log in.")
                st.session_state['page'] = 'login'
                st.experimental_rerun()

        if st.button("Already have an account? Log in here!"):
            st.session_state['page'] = 'login'
            st.experimental_rerun()

    elif page == 'login':
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")

            if submit:
                user = session.query(User).filter_by(username=username).first()
                if user and verify_password(user.password, password):
                    st.session_state['user'] = username
                    st.session_state['page'] = 'dashboard'
                    st.experimental_rerun()
                else:
                    st.error("Invalid username or password")

    elif page == 'dashboard':
        if 'user' in st.session_state:
            username = st.session_state['user']
            user = session.query(User).filter_by(username=username).first()

            st.subheader(f"Welcome, {username}")
            st.write("---")
            st.subheader("Manage your investment portfolio")
            stock_symbol = st.text_input("Enter stock ticker to add to portfolio")
            investment_amount = st.number_input("Investment Amount", min_value=0)
            add_button = st.button("Add to Portfolio")

            if add_button and stock_symbol and investment_amount > 0:
                new_entry = Portfolio(user_id=user.id, stock_symbol=stock_symbol, investment_amount=investment_amount)
                session.add(new_entry)
                session.commit()

            st.subheader("Your Portfolio")
            if user.portfolio:
                columns = st.columns(min(len(user.portfolio), 5))
                for idx, stock in enumerate(user.portfolio):
                    stock_info = yf.Ticker(stock.stock_symbol).info
                    with columns[idx]:
                        st.write(f"**{stock.stock_symbol}**")
                        st.write(f"Name: {stock_info.get('shortName', 'N/A')}")
                        st.write(f"Investment Amount: ${stock.investment_amount}")

                        if st.button(f"View {stock.stock_symbol}"):
                            st.session_state['stock_symbol'] = stock.stock_symbol
                            st.session_state['page'] = 'stock'
                            st.experimental_rerun()
                        if st.button(f"Remove {stock.stock_symbol}"):
                            session.query(Portfolio).filter_by(id=stock.id).delete()
                            session.commit()
                            st.experimental_rerun()  # Refresh the page to show updated portfolio
            else:
                st.write("No stocks in the portfolio.")

            st.subheader("Apply for a Loan")
            loan_amount = st.number_input("Loan Amount", min_value=0)
            interest_rate = st.number_input("Interest Rate (%)", min_value=0.0, format="%.2f")
            loan_term = st.number_input("Loan Term (months)", min_value=1)
            apply_loan_button = st.button("Apply for Loan")

            if apply_loan_button and loan_amount > 0 and interest_rate > 0 and loan_term > 0:
                new_loan = Loan(user_id=user.id, loan_amount=loan_amount, interest_rate=interest_rate, loan_term=loan_term)
                session.add(new_loan)
                session.commit()
                st.success("Loan application submitted!")

            st.subheader("Your Loans")
            if user.loans:
                for loan in user.loans:
                    st.write(f"Loan Amount: ${loan.loan_amount}")
                    st.write(f"Interest Rate: {loan.interest_rate}%")
                    st.write(f"Loan Term: {loan.loan_term} months")
                    st.write(f"Loan Status: {loan.loan_status}")
                    st.write("---")
            else:
                st.write("No loans applied.")

    elif page == 'stock':
        if 'stock_symbol' in st.session_state:
            user_input = st.session_state['stock_symbol']
            start = '2019-01-01'
            end = '2024-04-01'

            stock = yf.Ticker(user_input)
            df = stock.history(start=start, end=end)

            st.subheader(f'Data from 2019-2024 for {user_input}')
            st.write(df.describe())

            st.subheader('Closing Price vs Time chart')
            fig = plt.figure(figsize=(12, 6))
            plt.plot(df.Close)
            st.pyplot(fig)

            st.subheader('Closing Price vs Time chart with 100MA')
            ma100 = df.Close.rolling(100).mean()
            fig = plt.figure(figsize=(12, 6))
            plt.plot(ma100)
            plt.plot(df.Close)
            st.pyplot(fig)

            st.subheader('Closing Price vs Time chart with 100MA & 200MA')
            ma100 = df.Close.rolling(100).mean()
            ma200 = df.Close.rolling(200).mean()
            fig = plt.figure(figsize=(12, 6))
            plt.plot(ma100, 'r')
            plt.plot(ma200, 'g')
            plt.plot(df.Close, 'b')
            st.pyplot(fig)

            if st.button("Back to Dashboard"):
                st.session_state['page'] = 'dashboard'
                st.experimental_rerun()

# Run the main function
if __name__ == "__main__":
    Base.metadata.create_all(engine)
    main()