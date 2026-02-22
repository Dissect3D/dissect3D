import inspect

class PartCrafterPipeline(DiffusionPipeline, TransformerDiffusionMixin):
    """Pipeline for image to 3D Part Generation using PartCrafter"""
    def __init__(
        self,
        vae: TripoSGVAEModel,
        transformer: PartCrafterDiTModel,
        scheduler: FlowMatchEulerDiscreteScheduler,
        image_encoder_dinov2: DINOv2Model,
        feature_extractor: BitImageProcessor,
    ):
        super().__init__()
        self.register_modules(
            vae=vae,
            transformer=transformer,
            scheduler=scheduler,
            image_encoder_dinov2=image_encoder_dinov2,
            feature_extractor=feature_extractor,
        )