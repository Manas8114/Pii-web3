from inference import process_text
def answer(text: str):
    """
    Calls process_text() to analyze and anonymize text, then returns the final result.
    """
    anonymized_text = process_text(text)
    return anonymized_text

if __name__ == "__main__":
    user_input = """
    Hello, my name is David Johnson and I live in Maine.
I work as a software engineer at Amazon.
You can call me at (123) 456-7890.
My credit card number is 4095-2609-9393-4932 and my crypto wallet id is 16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ.
 
On September 18 I visited microsoft.com and sent an email to test@presidio.site, from the IP 192.168.0.1.
My passport: 191280342 and my phone number: (212) 555-1234.
This is a valid International Bank Account Number: IL150120690000003111111. Can you please check the status on bank account 954567876544?
Kate's social security number is 078-05-1126.  Her driver license? it is 1234567A.
"""
    print("\nFinal Answer:", answer(user_input))
