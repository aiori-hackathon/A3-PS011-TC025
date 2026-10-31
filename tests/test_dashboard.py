import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class DashboardImportTests(unittest.TestCase):
    def test_dashboard_imports_without_scanning_or_touching_project_database(self):
        script = (
            "import tempfile; from pathlib import Path; import database.db as db; "
            "temp = tempfile.TemporaryDirectory(); path = Path(temp.name) / 'test.db'; "
            "initialize = db.initialize_database; db.DB_PATH = path; "
            "db.initialize_database = lambda db_path=None: initialize(db_path or path); "
            "import dashboard; print('dashboard import OK')"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("dashboard import OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
