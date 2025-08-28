from transformers import AutoTokenizer, AutoModelForTokenClassification
from fastapi import FastAPI
import json

app = FastAPI()

# Load the tokenizer and model
tokenizer = AutoTokenizer.from_pretrained("ab-ai/PII-Model-Phi3-Mini")
model = AutoModelForTokenClassification.from_pretrained("ab-ai/PII-Model-Phi3-Mini")

# Define the PII detection endpoint
@app.post("/v1/extract_pii")
async def extract_pii(input_text: str):
    # Prepare the model prompt
    model_prompt = f"""### Instruction:
    Identify and extract the following PII entities from the text, if present: companyname, pin, currencyname, email, phoneimei, litecoinaddress, currency, eyecolor, street, mac, state, time, vehiclevin, jobarea, date, bic, currencysymbol, currencycode, age, nearbygpscoordinate, amount, ssn, ethereumaddress, zipcode, buildingnumber, dob, firstname, middlename, ordinaldirection, jobtitle, bitcoinaddress, jobtype, phonenumber, height, password, ip, useragent, accountname, city, gender, secondaryaddress, iban, sex, prefix, ipv4, maskednumber, url, username, lastname, creditcardcvv, county, vehiclevrm, ipv6, creditcardissuer, accountnumber, creditcardnumber. Return the output in JSON format.

    ### Input:
    {input_text}

    ### Output:
    """
#adding new data and functions
    # Tokenize the input text
    inputs = tokenizer(model_prompt, return_tensors="pt")

    # Run the model
    with torch.no_grad():
        outputs = model(**inputs)

    # Post-process the output and return it in JSON format
    pii_data = process_pii_output(outputs)
    return {"extracted_pii": pii_data}

def process_pii_output(outputs):
    # This function processes the model output to extract PII entities
    # and returns the result in a JSON format.
    entities = []
    for token, label in zip(outputs.tokens(), outputs.predictions()):
        if label != "O":  # Skip non-PII tokens
            entities.append({"token": token, "label": label})
    
    return json.dumps(entities)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
