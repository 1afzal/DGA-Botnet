from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from predict import bin_predict, multi_predict
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# Mount the 'static' directory for serving CSS files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup Jinja2 templates
templates = Jinja2Templates(directory="templates")

class DomainInput(BaseModel):
    domain_name: str

# HTML response for the main page with form
@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Endpoint to predict if domain is benign or malware
@app.post("/predict/")
def predict_domain(request: Request, domain_name: str = Form(...)):
    # Binary classification (malware or benign)
    binary_classifier = bin_predict(domain_name)
    is_malware = binary_classifier.predict()

    if is_malware == 0:
        return templates.TemplateResponse("index.html", {"request": {}, "domain_name": domain_name, "prediction": "Benign"})

    # If malware, perform multi-class classification to identify the malware family
    multi_classifier = multi_predict(domain_name)
    '''
    malware_family = multi_classifier.predict()

    return templates.TemplateResponse("index.html", {"request": {}, "domain_name": domain_name, "prediction": "Malware", "malware_family": malware_family})
    '''
    top_3_predictions = multi_classifier.predict()

    return templates.TemplateResponse(
        "index.html", 
        {
            "request": request, 
            "domain_name": domain_name, 
            "prediction": "Malware", 
            "top_3_predictions": top_3_predictions
        }
    )
    
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    domain_name = None
    prediction = None
    top_3_predictions = []
    
    if request.method == "POST":
        domain_name = request.form.get("domain_name")
        
        # Replace the following with your actual prediction logic:
        prediction = "Malware"  # Example prediction, replace with actual logic
        top_3_predictions = [
            {"class": "BotnetA", "probability": 0.85},
            {"class": "BotnetB", "probability": 0.75},
            {"class": "BotnetC", "probability": 0.65}
        ]
        
    return render_template("index.html", domain_name=domain_name, prediction=prediction, top_3_predictions=top_3_predictions)

if __name__ == "__main__":
    app.run(debug=True)


# uvicorn app:app --reload
