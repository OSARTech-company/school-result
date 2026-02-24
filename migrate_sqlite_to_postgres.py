import os
import sqlite3
from contextlib import closing

import psycopg2
from dotenv import load_dotenv


TABLES = [
    "users",
    "schools",
    "students",
    "teachers",
    "class_assignments",
    "class_subject_configs",
    "assessment_configs",
    "result_publications",
    "published_student_results",
    "result_views",
    "reports",
]

TABLE_COLUMNS = {
    "users": ["id", "username", "password_hash", "role", "school_id", "terms_accepted", "created_at"],
    "schools": [
        "id",
        "school_id",
        "school_name",
        "school_logo",
        "academic_year",
        "current_term",
        "operations_enabled",
        "test_enabled",
        "exam_enabled",
        "max_tests",
        "test_score_max",
        "exam_objective_max",
        "exam_theory_max",
        "grade_a_min",
        "grade_b_min",
        "grade_c_min",
        "grade_d_min",
        "pass_mark",
        "ss_ranking_mode",
        "ss1_stream_mode",
        "created_at",
    ],
    "students": [
        "id",
        "user_id",
        "school_id",
        "student_id",
        "firstname",
        "classname",
        "first_year_class",
        "term",
        "stream",
        "number_of_subject",
        "subjects",
        "scores",
        "promoted",
        "created_at",
    ],
    "teachers": ["id", "user_id", "school_id", "firstname", "lastname", "assigned_classes", "created_at"],
    "class_assignments": ["id", "school_id", "teacher_id", "classname", "term", "academic_year"],
    "class_subject_configs": [
        "id",
        "school_id",
        "classname",
        "core_subjects",
        "science_subjects",
        "art_subjects",
        "commercial_subjects",
        "optional_subjects",
        "optional_subject_limit",
        "created_at",
        "updated_at",
    ],
    "assessment_configs": [
        "id",
        "school_id",
        "level",
        "exam_mode",
        "objective_max",
        "theory_max",
        "exam_score_max",
        "updated_at",
    ],
    "result_publications": [
        "id",
        "school_id",
        "classname",
        "term",
        "teacher_id",
        "is_published",
        "published_at",
        "created_at",
        "updated_at",
    ],
    "published_student_results": [
        "id",
        "school_id",
        "student_id",
        "firstname",
        "classname",
        "academic_year",
        "term",
        "stream",
        "number_of_subject",
        "subjects",
        "scores",
        "teacher_comment",
        "average_marks",
        "grade",
        "status",
        "published_at",
    ],
    "result_views": [
        "id",
        "school_id",
        "student_id",
        "term",
        "academic_year",
        "first_viewed_at",
        "last_viewed_at",
        "view_count",
    ],
    "reports": ["id", "user_id", "description", "timestamp", "status", "read_at"],
}


def main():
    load_dotenv()
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set in environment/.env")

    sqlite_path = os.path.join(os.getcwd(), "student_score.db")
    if not os.path.exists(sqlite_path):
        raise RuntimeError(f"SQLite DB not found: {sqlite_path}")

    with closing(sqlite3.connect(sqlite_path)) as sconn, closing(psycopg2.connect(database_url)) as pconn:
        sconn.row_factory = sqlite3.Row
        pconn.autocommit = False

        with closing(sconn.cursor()) as scur, closing(pconn.cursor()) as pcur:
            # Clear existing data so migration is deterministic.
            pcur.execute("TRUNCATE TABLE " + ", ".join(TABLES) + " RESTART IDENTITY CASCADE;")

            for table in TABLES:
                cols = TABLE_COLUMNS[table]
                col_csv = ", ".join(cols)
                scur.execute(f"SELECT {col_csv} FROM {table}")
                rows = scur.fetchall()
                if rows:
                    placeholders = ", ".join(["%s"] * len(cols))
                    pcur.executemany(
                        f"INSERT INTO {table} ({col_csv}) VALUES ({placeholders})",
                        [tuple(row[c] for c in cols) for row in rows],
                    )
                print(f"{table}: {len(rows)} row(s)")

            # Ensure serial sequences continue after imported ids.
            for table in TABLES:
                pcur.execute(
                    "SELECT setval(pg_get_serial_sequence(%s, 'id'), COALESCE((SELECT MAX(id) FROM " + table + "), 1), true)",
                    (table,),
                )

            pconn.commit()
            print("Migration completed successfully.")


if __name__ == "__main__":
    main()
