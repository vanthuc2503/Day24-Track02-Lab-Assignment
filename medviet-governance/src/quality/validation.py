# src/quality/validation.py
"""
Data Quality Validation cho MedViet patient data.
Sử dụng Great Expectations để validate anonymized data.
"""
import os
import re
from pathlib import Path

import pandas as pd
import great_expectations as gx
from great_expectations.core.expectation_suite import ExpectationSuite


def build_patient_expectation_suite() -> ExpectationSuite:
    """
    Tạo expectation suite cho anonymized patient data.
    """
    # Resolve data path relative to project root
    project_root = Path(__file__).parent.parent.parent
    raw_data_path = project_root / "data" / "raw" / "patients_raw.csv"

    context = gx.get_context()
    suite = context.add_expectation_suite("patient_data_suite")

    # Lấy validator
    df = pd.read_csv(str(raw_data_path))
    validator = context.sources.pandas_default.read_dataframe(df)

    # --- TASK: Thêm các expectations ---

    # 1. patient_id không được null
    validator.expect_column_values_to_not_be_null("patient_id")

    # 2. cccd phải có đúng 12 ký tự
    validator.expect_column_value_lengths_to_equal(
        column="cccd",
        value=12,
    )

    # 3. ket_qua_xet_nghiem phải trong khoảng [0, 50]
    validator.expect_column_values_to_be_between(
        column="ket_qua_xet_nghiem",
        min_value=0,
        max_value=50,
    )

    # 4. benh phải thuộc danh sách hợp lệ
    valid_conditions = ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]
    validator.expect_column_values_to_be_in_set(
        column="benh",
        value_set=valid_conditions,
    )

    # 5. email phải match regex pattern
    validator.expect_column_values_to_match_regex(
        column="email",
        regex=r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    )

    # 6. Không được có duplicate patient_id
    validator.expect_column_values_to_be_unique(column="patient_id")

    validator.save_expectation_suite()
    return suite


def validate_anonymized_data(filepath: str) -> dict:
    """
    Validate anonymized data.
    Trả về dict: {"success": bool, "failed_checks": list, "stats": dict}
    """
    df = pd.read_csv(filepath)
    results = {
        "success": True,
        "failed_checks": [],
        "stats": {
            "total_rows": len(df),
            "columns": list(df.columns)
        }
    }

    # Check 1: Không còn CCCD gốc dạng số thuần túy
    # (sau anonymization, cccd phải là fake hoặc masked)
    # Pattern cho số CCCD gốc: đúng 12 chữ số liên tiếp
    cccd_pattern = re.compile(r"^\d{12}$")
    original_cccd_found = False
    for val in df["cccd"].astype(str):
        if cccd_pattern.match(val):
            original_cccd_found = True
            results["failed_checks"].append(
                "Original CCCD pattern (12 digits) still present in anonymized data"
            )
            results["success"] = False
            break

    # Check 2: Không có null values trong các cột quan trọng
    important_cols = ["patient_id", "cccd", "so_dien_thoai", "email"]
    for col in important_cols:
        if col in df.columns:
            null_count = df[col].isnull().sum()
            if null_count > 0:
                results["failed_checks"].append(
                    f"Column '{col}' has {null_count} null values"
                )
                results["success"] = False

    # Check 3: Số rows phải bằng original
    project_root = Path(__file__).parent.parent.parent
    raw_path = project_root / "data" / "raw" / "patients_raw.csv"
    if raw_path.exists():
        original_df = pd.read_csv(str(raw_path))
        if len(df) != len(original_df):
            results["failed_checks"].append(
                f"Row count mismatch: anonymized={len(df)}, original={len(original_df)}"
            )
            results["success"] = False

    return results


def validate_data_quality(df: pd.DataFrame) -> dict:
    """
    Quick validation cho DataFrame.
    Trả về dict với validation results.
    """
    results = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "stats": {
            "total_rows": len(df),
            "total_columns": len(df.columns),
            "null_counts": df.isnull().sum().to_dict()
        }
    }

    # Check 1: CCCD phải có 12 ký tự
    if "cccd" in df.columns:
        invalid_cccd = df[~df["cccd"].astype(str).str.match(r"^\d{12}$")]
        if len(invalid_cccd) > 0:
            results["errors"].append(
                f"Found {len(invalid_cccd)} invalid CCCD values (not 12 digits)"
            )
            results["valid"] = False

    # Check 2: Số điện thoại phải có 10 ký tự bắt đầu bằng 0
    if "so_dien_thoai" in df.columns:
        invalid_phone = df[~df["so_dien_thoai"].astype(str).str.match(r"^0\d{9}$")]
        if len(invalid_phone) > 0:
            results["errors"].append(
                f"Found {len(invalid_phone)} invalid phone numbers"
            )
            results["valid"] = False

    # Check 3: Email phải match pattern
    if "email" in df.columns:
        email_pattern = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
        invalid_email = df[~df["email"].astype(str).apply(lambda x: bool(email_pattern.match(x)))]
        if len(invalid_email) > 0:
            results["errors"].append(
                f"Found {len(invalid_email)} invalid email values"
            )
            results["valid"] = False

    # Check 4: ket_qua_xet_nghiem phải trong khoảng [0, 50]
    if "ket_qua_xet_nghiem" in df.columns:
        out_of_range = df[
            (df["ket_qua_xet_nghiem"] < 0) | (df["ket_qua_xet_nghiem"] > 50)
        ]
        if len(out_of_range) > 0:
            results["warnings"].append(
                f"Found {len(out_of_range)} ket_qua_xet_nghiem values out of [0, 50] range"
            )

    # Check 5: benh phải thuộc danh sách hợp lệ
    if "benh" in df.columns:
        valid_conditions = ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]
        invalid_benh = df[~df["benh"].isin(valid_conditions)]
        if len(invalid_benh) > 0:
            results["warnings"].append(
                f"Found {len(invalid_benh)} benh values not in expected set"
            )

    # Check 6: patient_id phải unique
    if "patient_id" in df.columns:
        duplicates = df["patient_id"].duplicated().sum()
        if duplicates > 0:
            results["errors"].append(
                f"Found {duplicates} duplicate patient_id values"
            )
            results["valid"] = False

    return results
