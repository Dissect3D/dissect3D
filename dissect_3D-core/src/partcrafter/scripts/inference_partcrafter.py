import torch

from common.setting.device import get_device
from common.image_processing.remove_background import remove_background
from environment.memory import clear_memory

class PartCrafterService:
    def __init__(self):
        self.pipe = None
        self.device = get_device()

    def load(self):
        # TODO: Create pipeline
        if self.pipe is None:
            """Load the main 3D generation pipeline"""
            # self.pipe = 
            pass
        self.pipe.to(self.device)
    
    def remove_background(self, image):
        """Remove background from image using cached RMBG model"""
        return remove_background(image)
    
    def generate_3d(self, image):
        """Generate 3D model from image"""
        start_time = time.time()
        output = self.pipe(image)

    def unload(self, delete=False):
        if self.pipe is not None:
            if delete:
                del self.pipe
                self.pipe = None
            else:
                self.pipe.to("cpu")
            clear_memory()
    
        
