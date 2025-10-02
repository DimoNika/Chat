

# print("hello worlkd")
from fastapi import FastAPI
import uvicorn

# while True:
#     pass
app = FastAPI()

@app.get("/test")
async def main():
    return "hello world hehe"




# if __name__ == "__main__":
#     uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)