# src/api/main.py
"""
MedViet Data API - FastAPI với RBAC.
Chạy: uvicorn src.api.main:app --reload
"""
import os
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException
import pandas as pd

from src.access.rbac import get_current_user, require_permission
from src.pii.anonymizer import MedVietAnonymizer

app = FastAPI(title="MedViet Data API", version="1.0.0")
anonymizer = MedVietAnonymizer()

# Resolve data paths relative to project root
_project_root = Path(__file__).parent.parent.parent
_raw_data_path = _project_root / "data" / "raw" / "patients_raw.csv"
_processed_data_path = _project_root / "data" / "processed" / "patients_anonymized.csv"


# --- ENDPOINT 1 ---
@app.get("/api/patients/raw")
async def get_raw_patients(
    current_user: dict = Depends(get_current_user),
):
    """
    Trả về raw patient data (chỉ admin được phép).
    Load từ data/raw/patients_raw.csv
    Trả về 10 records đầu tiên dưới dạng JSON.
    """
    allowed = (
        current_user["role"] == "admin"
    )
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{current_user['role']}' cannot read raw patient data"
        )

    if not _raw_data_path.exists():
        raise HTTPException(status_code=404, detail="Raw data file not found")

    df = pd.read_csv(_raw_data_path)
    return {
        "total": len(df),
        "records": df.head(10).to_dict(orient="records"),
    }


# --- ENDPOINT 2 ---
@app.get("/api/patients/anonymized")
async def get_anonymized_patients(
    current_user: dict = Depends(get_current_user),
):
    """
    Trả về anonymized data (ml_engineer và admin được phép).
    Load raw data → anonymize → trả về JSON.
    """
    allowed = current_user["role"] in ("admin", "ml_engineer")
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{current_user['role']}' cannot read anonymized data"
        )

    if not _raw_data_path.exists():
        raise HTTPException(status_code=404, detail="Raw data file not found")

    df = pd.read_csv(_raw_data_path)
    df_anon = anonymizer.anonymize_dataframe(df)

    return {
        "total": len(df_anon),
        "records": df_anon.head(10).to_dict(orient="records"),
    }


# --- ENDPOINT 3 ---
@app.get("/api/metrics/aggregated")
async def get_aggregated_metrics(
    current_user: dict = Depends(get_current_user),
):
    """
    Trả về aggregated metrics (data_analyst, ml_engineer, admin).
    Ví dụ: số bệnh nhân theo từng loại bệnh (không có PII).
    """
    allowed = current_user["role"] in (
        "admin", "ml_engineer", "data_analyst"
    )
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{current_user['role']}' cannot read aggregated metrics"
        )

    if not _raw_data_path.exists():
        raise HTTPException(status_code=404, detail="Data file not found")

    df = pd.read_csv(_raw_data_path)

    # Tổng số bệnh nhân
    total_patients = len(df)

    # Số bệnh nhân theo loại bệnh
    by_disease = df["benh"].value_counts().to_dict()

    # Thống kê ket_qua_xet_nghiem
    kqxn_stats = {
        "mean": round(df["ket_qua_xet_nghiem"].mean(), 2),
        "min": round(df["ket_qua_xet_nghiem"].min(), 2),
        "max": round(df["ket_qua_xet_nghiem"].max(), 2),
    }

    # Số bệnh nhân theo bác sĩ phụ trách
    by_doctor = df["bac_si_phu_trach"].value_counts().to_dict()

    return {
        "total_patients": total_patients,
        "by_disease": by_disease,
        "ket_qua_xet_nghiem_stats": kqxn_stats,
        "unique_doctors": len(by_doctor),
    }


# --- ENDPOINT 4 ---
@app.delete("/api/patients/{patient_id}")
async def delete_patient(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Chỉ admin được xóa. Các role khác nhận 403.
    """
    allowed = current_user["role"] == "admin"
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{current_user['role']}' cannot delete patient data"
        )

    if not _raw_data_path.exists():
        raise HTTPException(status_code=404, detail="Data file not found")

    df = pd.read_csv(_raw_data_path)

    if patient_id not in df["patient_id"].values:
        raise HTTPException(status_code=404, detail="Patient not found")

    df = df[df["patient_id"] != patient_id]
    df.to_csv(_raw_data_path, index=False)

    return {
        "status": "deleted",
        "patient_id": patient_id,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "MedViet Data API"}
