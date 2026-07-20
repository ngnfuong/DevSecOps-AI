import os
import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock

# Them thu muc goc vao sys.path de import auto_remediate_rag
_BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BASE_DIR))

from auto_remediate_rag import (
    detect_language,
    get_project_and_file_path,
    get_build_command,
    check_build_success,
    _extract_cwe_from_finding,
    group_vulns_by_file
)

def test_detect_language():
    assert detect_language("src/main/java/com/devsecops/UserController.java")["name"] == "Java"
    assert detect_language("vulnerable-python-app/app.py")["name"] == "Python"
    assert detect_language("index.js")["name"] == "JavaScript"
    # Fallback to Java if unknown
    assert detect_language("unknown.txt")["name"] == "Java"

def test_get_project_and_file_path():
    # Kiem tra xem duong dan co duoc tra ve dung theo cau hinh PROJECT_PATH khong
    project_path, target_file = get_project_and_file_path("src/main/java/com/devsecops/UserController.java")
    assert "vulnerable-spring-boot" in project_path
    assert target_file == "src/main/java/com/devsecops/UserController.java"

def test_get_build_command(monkeypatch):
    # Mock os.path.exists de kiem tra viec phat hien pom.xml hoac build.gradle
    def mock_exists_java_maven(path):
        if "pom.xml" in str(path): return True
        return False
    
    monkeypatch.setattr(os.path, "exists", mock_exists_java_maven)
    cmd_java = get_build_command("Java", "dummy_project_path", "dummy.java")
    assert "mvn" in cmd_java
    assert "compile" in cmd_java
    
    def mock_exists_python_pytest(path):
        if "requirements.txt" in str(path): return True
        return False
    
    monkeypatch.setattr(os.path, "exists", mock_exists_python_pytest)
    cmd_python_pytest = get_build_command("Python", "dummy_project_path", "dummy.py")
    assert "py_compile" in cmd_python_pytest # Python currently uses py_compile, we reverted the pytest logic earlier
    
    def mock_exists_python_nopytest(path):
        return False
    
    monkeypatch.setattr(os.path, "exists", mock_exists_python_nopytest)
    cmd_python_nopytest = get_build_command("Python", "dummy_project_path", "dummy.py")
    assert "py_compile" in cmd_python_nopytest
    assert "dummy.py" in cmd_python_nopytest[-1]

def test_check_build_success():
    mock_result_java_pass = MagicMock()
    mock_result_java_pass.returncode = 0
    mock_result_java_pass.stdout = "BUILD SUCCESS"
    mock_result_java_pass.stderr = ""
    assert check_build_success(mock_result_java_pass, "Java") == True
    
    mock_result_java_fail = MagicMock()
    mock_result_java_fail.returncode = 1
    mock_result_java_fail.stdout = "BUILD FAILURE"
    mock_result_java_fail.stderr = "ERROR"
    assert check_build_success(mock_result_java_fail, "Java") == False
    
    mock_result_python_pass = MagicMock()
    mock_result_python_pass.returncode = 0
    assert check_build_success(mock_result_python_pass, "Python") == True

def test_extract_cwe_from_finding():
    assert _extract_cwe_from_finding("CWE-89 SQL Injection", "") == "CWE-89"
    assert _extract_cwe_from_finding("Random vuln", "This is related to CWE-78 command injection") == "CWE-78"
    assert _extract_cwe_from_finding("No CWE here", "No description") == "UNKNOWN"

def test_group_vulns_by_file(monkeypatch):
    # Mock os.path.exists so _resolve_target_file doesn't fallback to _DEFAULT_FILE
    monkeypatch.setattr(os.path, "exists", lambda path: True)
    findings = [
        {"file_path": "vulnerable-python-app/file2.py", "title": "Vuln C"},
        {"title": "Vuln D without file_path"}
    ]
    grouped = group_vulns_by_file(findings)
    assert len(grouped) == 2
    assert len(grouped["vulnerable-python-app/file2.py"]) == 1
