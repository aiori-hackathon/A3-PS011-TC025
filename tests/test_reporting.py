import tempfile
import unittest
from pathlib import Path

from database.db import initialize_database
from reports.report_generator import generate_pdf_report


class ReportGeneratorTests(unittest.TestCase):
    def test_generates_pdf_bytes_and_optional_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            db_path = root / "report.db"
            output_path = root / "reports" / "report.pdf"
            initialize_database(db_path)

            report = generate_pdf_report(output_path, db_path)

            self.assertTrue(report.startswith(b"%PDF-"))
            self.assertEqual(output_path.read_bytes(), report)


if __name__ == "__main__":
    unittest.main()
