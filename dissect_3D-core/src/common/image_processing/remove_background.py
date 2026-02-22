from transformers import AutoModelForImageSegmentation
import torch

from common.setting.device import get_device

_RMBG_MODEL = None

def prepare_rmbg_model(model_path=""):
    """Returns the model if loaded, else load the model"""
    global _RMBG_MODEL
    # TODO: Load model
    if _RMBG_MODEL is None:
        print(f"Loading background removal model from {model_path}...")
        _RMBG_MODEL = AutoModelForImageSegmentation.from_pretrained(
            model_path, 
            trust_remote_code=True, 
            device_map="auto"
        )
        _RMBG_MODEL.eval()
    print("Load background removal model successfully")
    return _RMBG_MODEL


def remove_background(image):
    model = prepare_rmbg_model()
    device = get_device()

    image_size = (1024, 1024)
    # TODO: Setup global image size
    transform_image = transforms.Compose([
        transforms.Resize(image_size),
        transforms.ToTensor(),
        transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
    ])

    input_images = transform_image(image).unsqueeze(0).to(device)
    with torch.no_grad():
        pred = model(input_images)[-1].sigmoid().cpu()
    pred = pred[0].squeeze()
    pred_pil = transforms.ToPILImage()(pred)
    mask = pred_pil.resize(image.size)
    image.putalpha(mask)
    
    return image