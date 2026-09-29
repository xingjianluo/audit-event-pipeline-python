import uvicorn
from fastapi import FastAPI

from audit_pipeline.api import register_audit_routes

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


register_audit_routes(app)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
