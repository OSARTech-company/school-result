import sys
sys.path.insert(0, 'c:/Aka/my.py')

try:
    from student_scor import app
    print('App loaded successfully')
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
