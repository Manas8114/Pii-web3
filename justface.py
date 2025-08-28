import fitz  # PyMuPDF
import cv2
import numpy as np
from PIL import Image
import io

# Load OpenCV's pre-trained Haar cascade for face detection
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")

def blur_faces_in_image(image):
    """ Detects and blurs faces in an image """
    image_cv2 = np.array(image)  # Convert PIL image to OpenCV format
    image_cv2 = cv2.cvtColor(image_cv2, cv2.COLOR_RGB2BGR)  # Convert to BGR

    gray = cv2.cvtColor(image_cv2, cv2.COLOR_BGR2GRAY)  # Convert to grayscale
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

    for (x, y, w, h) in faces:
        face_region = image_cv2[y:y+h, x:x+w]
        blurred_face = cv2.GaussianBlur(face_region, (99, 99), 30)  # Apply Gaussian blur
        image_cv2[y:y+h, x:x+w] = blurred_face

    return Image.fromarray(cv2.cvtColor(image_cv2, cv2.COLOR_BGR2RGB))  # Convert back to PIL image

def process_pdf(pdf_path, output_pdf_path="blurred_output.pdf"):
    """ Extracts images from a PDF, applies face blurring, and saves a new PDF with blurred images in the same position and size. """
    doc = fitz.open(pdf_path)  # Open the PDF

    for page_num in range(len(doc)):
        page = doc[page_num]
        img_list = page.get_images(full=True)  # Get all images on the page
        
        for img_index, img_info in enumerate(img_list):
            xref = img_info[0]  # Image reference
            base_image = fitz.Pixmap(doc, xref)

            # Convert image to PIL
            img_pil = Image.frombytes("RGB", [base_image.width, base_image.height], base_image.samples)

            # Apply face blurring
            blurred_image = blur_faces_in_image(img_pil)

            # Convert blurred image to bytes
            img_byte_arr = io.BytesIO()
            blurred_image.save(img_byte_arr, format="PNG")
            img_bytes = img_byte_arr.getvalue()

            # Get image position on the page
            for img_index, img in enumerate(page.get_images(full=True)):
                if img[0] == xref:
                    img_rect = page.get_image_rects(xref)[0]  # Get image position

                    # Replace the image in the exact position and size
                    page.insert_image(img_rect, stream=img_bytes)

    # Save the modified PDF
    doc.save(output_pdf_path)
    doc.close()
    print(f"Blurred PDF saved as {output_pdf_path}")

def process_image(image_path, output_image_path="blurred_image.jpg"):
    """ Loads an image, applies face blurring, and saves the output """
    image = Image.open(image_path)
    blurred_image = blur_faces_in_image(image)
    blurred_image.save(output_image_path)
    print(f"Blurred image saved as {output_image_path}")

def main(input_path):
    """ Detects input type and processes accordingly """
    if input_path.lower().endswith(".pdf"):
        process_pdf(input_path)
    elif input_path.lower().endswith((".jpg", ".jpeg", ".png")):
        process_image(input_path)
    else:
        print("Unsupported file format. Please use a PDF or an image.")

# Example usage
if __name__ == "__main__":
    input_path = r"D:\CodeFest(tokenization)\Codefest_Token\image.png"  # Change to your file path
    main(input_path)


