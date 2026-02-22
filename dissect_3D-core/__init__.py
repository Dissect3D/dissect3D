import bpy

bl_info = {
    "name": "Simple UI Extension",
    "author": "Your Name",
    "version": (1, 0),
    "blender": (4, 2, 0),       # Minimum version for the Extension system
    "location": "View3D > Sidebar > MyTab",
    "description": "A simple UI extension",
    "category": "Interface",
    "type": "extension",        # <--- TELLS BLENDER 5.0 THIS IS AN EXTENSION
}

class SIMPLE_PT_CustomPanel(bpy.types.Panel):
    """Creates a Panel in the Object properties window"""
    bl_label = "My Custom Panel"
    bl_idname = "SIMPLE_PT_custom_panel"
    bl_space_type = "VIEW_3D"
    bl_region_type = "UI"
    bl_category = "MyTab"

    def draw(self, context):
        layout = self.layout
        obj = context.object

        layout.label(text="Hello World")

        layout.operator("mesh.primitive_cuba_add", text="Add a Cube")

        if obj:
            layout.prop(obj, "name")

def register():
    bpy.utils.register_class(SIMPLE_PT_CustomPanel)

def unregister():
    bpy.utils.unregister_class(SIMPLE_PT_CustomPanel)

if __name__ == "__main__":
    register()