import face_recognition
import numpy as np
from PIL import Image
from io import BytesIO
import base64

def match_faces(known_path, unknown_base64):
    known = face_recognition.load_image_file(known_path)
    known_encoding = face_recognition.face_encodings(known)[0]

    unknown_data = base64.b64decode(unknown_base64.split(',')[1])
    unknown_image = Image.open(BytesIO(unknown_data))
    unknown_np = np.array(unknown_image)
    unknown_encodings = face_recognition.face_encodings(unknown_np)

    if not unknown_encodings:
        return False
    return face_recognition.compare_faces([known_encoding], unknown_encodings[0])[0]
