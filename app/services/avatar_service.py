from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import hashlib
import secrets
import base64
import io
from PIL import Image
import structlog
from pathlib import Path
import aiofiles
import httpx

from app.core.config import settings
from app.core.exceptions import ValidationError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class AvatarService:
    """
    Avatar management service for user profile images
    """
    
    def __init__(self):
        self.max_file_size = 5 * 1024 * 1024  # 5MB
        self.allowed_formats = {"jpeg", "jpg", "png", "gif", "webp"}
        self.thumbnail_sizes = {
            "small": (50, 50),
            "medium": (150, 150),
            "large": (300, 300)
        }
        self.default_avatar_size = (200, 200)
        self.storage_path = Path(settings.UPLOAD_DIR if hasattr(settings, 'UPLOAD_DIR') else "./uploads/avatars")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def upload_avatar(
        self,
        user_id: str,
        file_data: bytes,
        filename: str,
        content_type: str
    ) -> Dict[str, Any]:
        """
        Upload and process user avatar
        """
        try:
            # Validate file
            self._validate_file(file_data, filename, content_type)
            
            # Process image
            image = Image.open(io.BytesIO(file_data))
            
            # Convert to RGB if necessary (for PNG with transparency)
            if image.mode in ('RGBA', 'LA', 'P'):
                rgb_image = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'RGBA':
                    rgb_image.paste(image, mask=image.split()[3])
                else:
                    rgb_image.paste(image)
                image = rgb_image
            
            # Generate unique filename
            file_ext = self._get_file_extension(filename, content_type)
            unique_filename = self._generate_unique_filename(user_id, file_ext)
            
            # Create different sizes
            sizes_created = {}
            
            # Original size (but limited to max dimensions)
            original = self._resize_image(image, (800, 800), maintain_aspect=True)
            original_path = self.storage_path / f"{unique_filename}_original.{file_ext}"
            await self._save_image(original, original_path, file_ext)
            sizes_created["original"] = str(original_path)
            
            # Create thumbnails
            for size_name, dimensions in self.thumbnail_sizes.items():
                thumbnail = self._resize_image(image, dimensions)
                thumb_path = self.storage_path / f"{unique_filename}_{size_name}.{file_ext}"
                await self._save_image(thumbnail, thumb_path, file_ext)
                sizes_created[size_name] = str(thumb_path)
            
            # Generate avatar URL (for serving)
            avatar_url = self._generate_avatar_url(unique_filename, file_ext)
            
            # Update user profile in Clerk
            clerk_client = await self._get_clerk_client()
            await clerk_client.update_user(
                user_id=user_id,
                public_metadata={
                    "avatar_url": avatar_url,
                    "avatar_sizes": sizes_created,
                    "avatar_updated_at": datetime.utcnow().isoformat()
                }
            )
            
            # Store avatar info in cache for quick access
            avatar_key = f"avatar:{user_id}"
            avatar_data = {
                "user_id": user_id,
                "filename": unique_filename,
                "original_filename": filename,
                "format": file_ext,
                "sizes": sizes_created,
                "url": avatar_url,
                "uploaded_at": datetime.utcnow().isoformat(),
                "file_size": len(file_data)
            }
            await cache_service.set(avatar_key, avatar_data, expire=86400)  # Cache for 24 hours
            
            # Clean up old avatars
            await self._cleanup_old_avatars(user_id, unique_filename)
            
            logger.info(f"Avatar uploaded for user {user_id}", filename=unique_filename)
            
            return {
                "avatar_url": avatar_url,
                "sizes": {
                    "small": self._generate_avatar_url(unique_filename, file_ext, "small"),
                    "medium": self._generate_avatar_url(unique_filename, file_ext, "medium"),
                    "large": self._generate_avatar_url(unique_filename, file_ext, "large"),
                    "original": avatar_url
                },
                "format": file_ext,
                "file_size": len(file_data),
                "uploaded_at": avatar_data["uploaded_at"]
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to upload avatar: {str(e)}")
            raise ValidationError("Failed to upload avatar")
    
    async def remove_avatar(self, user_id: str) -> Dict[str, Any]:
        """
        Remove user's avatar and set to default
        """
        try:
            # Get current avatar info
            avatar_key = f"avatar:{user_id}"
            avatar_data = await cache_service.get(avatar_key)
            
            if avatar_data:
                # Delete avatar files
                for size_path in avatar_data.get("sizes", {}).values():
                    try:
                        path = Path(size_path)
                        if path.exists():
                            path.unlink()
                    except Exception as e:
                        logger.error(f"Failed to delete avatar file: {str(e)}")
            
            # Clear cache
            await cache_service.delete(avatar_key)
            
            # Update user profile in Clerk
            clerk_client = await self._get_clerk_client()
            await clerk_client.update_user(
                user_id=user_id,
                public_metadata={
                    "avatar_url": None,
                    "avatar_sizes": None,
                    "avatar_removed_at": datetime.utcnow().isoformat()
                }
            )
            
            # Generate default avatar
            default_avatar = await self.generate_default_avatar(user_id)
            
            logger.info(f"Avatar removed for user {user_id}")
            
            return {
                "removed": True,
                "default_avatar": default_avatar,
                "message": "Avatar removed successfully"
            }
        
        except Exception as e:
            logger.error(f"Failed to remove avatar: {str(e)}")
            raise ValidationError("Failed to remove avatar")
    
    async def get_avatar(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user's avatar information
        """
        try:
            # Check cache first
            avatar_key = f"avatar:{user_id}"
            avatar_data = await cache_service.get(avatar_key)
            
            if avatar_data:
                return avatar_data
            
            # Get from Clerk if not in cache
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if user and user.public_metadata:
                avatar_url = user.public_metadata.get("avatar_url")
                if avatar_url:
                    return {
                        "avatar_url": avatar_url,
                        "sizes": user.public_metadata.get("avatar_sizes", {}),
                        "uploaded_at": user.public_metadata.get("avatar_updated_at")
                    }
            
            # Return default avatar
            default_avatar = await self.generate_default_avatar(user_id)
            return {"avatar_url": default_avatar, "is_default": True}
        
        except Exception as e:
            logger.error(f"Failed to get avatar: {str(e)}")
            return None
    
    async def generate_default_avatar(
        self,
        user_id: str,
        name: Optional[str] = None
    ) -> str:
        """
        Generate default avatar (initials or identicon)
        """
        try:
            if name:
                # Generate initials avatar
                initials = self._get_initials(name)
                return await self._generate_initials_avatar(initials, user_id)
            else:
                # Generate identicon
                return self._generate_identicon(user_id)
        
        except Exception as e:
            logger.error(f"Failed to generate default avatar: {str(e)}")
            # Return a generic avatar URL
            return f"https://ui-avatars.com/api/?name={user_id[:2]}&background=random"
    
    async def update_avatar_from_url(
        self,
        user_id: str,
        image_url: str
    ) -> Dict[str, Any]:
        """
        Update avatar from an external URL (e.g., social login)
        """
        try:
            # Download image
            async with httpx.AsyncClient() as client:
                response = await client.get(image_url, timeout=10.0)
                response.raise_for_status()
                
                file_data = response.content
                content_type = response.headers.get("content-type", "image/jpeg")
                
                # Extract filename from URL or use default
                filename = image_url.split("/")[-1].split("?")[0]
                if not filename or "." not in filename:
                    filename = f"avatar_{user_id}.jpg"
                
                # Upload the avatar
                return await self.upload_avatar(
                    user_id=user_id,
                    file_data=file_data,
                    filename=filename,
                    content_type=content_type
                )
        
        except httpx.HTTPError as e:
            logger.error(f"Failed to download avatar from URL: {str(e)}")
            raise ValidationError("Failed to download avatar from URL")
        except Exception as e:
            logger.error(f"Failed to update avatar from URL: {str(e)}")
            raise ValidationError("Failed to update avatar from URL")
    
    async def crop_avatar(
        self,
        user_id: str,
        crop_data: Dict[str, int]
    ) -> Dict[str, Any]:
        """
        Crop existing avatar
        crop_data: {x: int, y: int, width: int, height: int}
        """
        try:
            # Get current avatar
            avatar_data = await self.get_avatar(user_id)
            if not avatar_data or avatar_data.get("is_default"):
                raise ValidationError("No avatar to crop")
            
            # Load original image
            original_path = None
            for size_name, path in avatar_data.get("sizes", {}).items():
                if "original" in size_name:
                    original_path = path
                    break
            
            if not original_path:
                raise ValidationError("Original avatar not found")
            
            # Open and crop image
            image = Image.open(original_path)
            cropped = image.crop((
                crop_data["x"],
                crop_data["y"],
                crop_data["x"] + crop_data["width"],
                crop_data["y"] + crop_data["height"]
            ))
            
            # Save cropped version as new avatar
            output = io.BytesIO()
            cropped.save(output, format='JPEG', quality=90)
            output.seek(0)
            
            return await self.upload_avatar(
                user_id=user_id,
                file_data=output.getvalue(),
                filename="cropped_avatar.jpg",
                content_type="image/jpeg"
            )
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to crop avatar: {str(e)}")
            raise ValidationError("Failed to crop avatar")
    
    # ============= Helper Methods =============
    
    def _validate_file(self, file_data: bytes, filename: str, content_type: str):
        """Validate uploaded file"""
        # Check file size
        if len(file_data) > self.max_file_size:
            raise ValidationError(f"File size exceeds {self.max_file_size // (1024*1024)}MB limit")
        
        # Check content type
        if not content_type.startswith("image/"):
            raise ValidationError("File must be an image")
        
        # Check file extension
        file_ext = self._get_file_extension(filename, content_type)
        if file_ext not in self.allowed_formats:
            raise ValidationError(f"Invalid image format. Allowed: {', '.join(self.allowed_formats)}")
        
        # Validate it's actually an image
        try:
            image = Image.open(io.BytesIO(file_data))
            image.verify()
        except Exception:
            raise ValidationError("Invalid image file")
    
    def _get_file_extension(self, filename: str, content_type: str) -> str:
        """Get file extension from filename or content type"""
        # Try to get from filename
        if "." in filename:
            ext = filename.rsplit(".", 1)[1].lower()
            if ext in self.allowed_formats:
                return ext
        
        # Get from content type
        content_type_map = {
            "image/jpeg": "jpg",
            "image/jpg": "jpg",
            "image/png": "png",
            "image/gif": "gif",
            "image/webp": "webp"
        }
        
        return content_type_map.get(content_type, "jpg")
    
    def _generate_unique_filename(self, user_id: str, extension: str) -> str:
        """Generate unique filename for avatar"""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        random_str = secrets.token_hex(4)
        return f"{user_id}_{timestamp}_{random_str}"
    
    def _resize_image(
        self,
        image: Image.Image,
        size: Tuple[int, int],
        maintain_aspect: bool = False
    ) -> Image.Image:
        """Resize image to specified dimensions"""
        if maintain_aspect:
            image.thumbnail(size, Image.Resampling.LANCZOS)
            return image
        else:
            return image.resize(size, Image.Resampling.LANCZOS)
    
    async def _save_image(self, image: Image.Image, path: Path, format: str):
        """Save image to disk"""
        # Convert format name
        save_format = "JPEG" if format in ["jpg", "jpeg"] else format.upper()
        
        # Save with appropriate quality
        quality = 90 if save_format == "JPEG" else None
        
        output = io.BytesIO()
        if quality:
            image.save(output, format=save_format, quality=quality, optimize=True)
        else:
            image.save(output, format=save_format, optimize=True)
        
        output.seek(0)
        
        # Write to file
        async with aiofiles.open(path, 'wb') as f:
            await f.write(output.getvalue())
    
    def _generate_avatar_url(
        self,
        filename: str,
        extension: str,
        size: Optional[str] = None
    ) -> str:
        """Generate URL for serving avatar"""
        base_url = settings.BASE_URL if hasattr(settings, 'BASE_URL') else "http://localhost:8000"
        size_suffix = f"_{size}" if size else "_original"
        return f"{base_url}/api/v1/users/avatar/{filename}{size_suffix}.{extension}"
    
    async def _cleanup_old_avatars(self, user_id: str, current_filename: str):
        """Clean up old avatar files for user"""
        try:
            # List all files in avatar directory
            for file_path in self.storage_path.glob(f"{user_id}_*"):
                # Skip current avatar files
                if current_filename not in str(file_path):
                    try:
                        file_path.unlink()
                    except Exception as e:
                        logger.error(f"Failed to delete old avatar: {str(e)}")
        
        except Exception as e:
            logger.error(f"Failed to cleanup old avatars: {str(e)}")
    
    def _get_initials(self, name: str) -> str:
        """Extract initials from name"""
        parts = name.strip().split()
        if len(parts) >= 2:
            return f"{parts[0][0]}{parts[-1][0]}".upper()
        elif parts:
            return parts[0][:2].upper()
        return "??"
    
    async def _generate_initials_avatar(self, initials: str, user_id: str) -> str:
        """Generate avatar with initials"""
        try:
            # Create image with initials
            size = self.default_avatar_size
            background_color = self._generate_color_from_id(user_id)
            
            image = Image.new('RGB', size, color=background_color)
            
            # Add initials (requires PIL font support)
            # For simplicity, returning external service URL
            return f"https://ui-avatars.com/api/?name={initials}&background={background_color[1:]}&color=fff&size={size[0]}"
        
        except Exception as e:
            logger.error(f"Failed to generate initials avatar: {str(e)}")
            return f"https://ui-avatars.com/api/?name={initials}&background=random"
    
    def _generate_identicon(self, user_id: str) -> str:
        """Generate identicon avatar"""
        # Use external service for identicon generation
        hash_str = hashlib.md5(user_id.encode()).hexdigest()
        return f"https://identicon.net/?t={hash_str}&s=200"
    
    def _generate_color_from_id(self, user_id: str) -> str:
        """Generate consistent color from user ID"""
        hash_obj = hashlib.md5(user_id.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Use first 6 characters for color
        return f"#{hash_hex[:6]}"
    
    async def get_avatar_stats(self, user_id: str) -> Dict[str, Any]:
        """Get avatar statistics for user"""
        try:
            avatar_data = await self.get_avatar(user_id)
            
            if not avatar_data or avatar_data.get("is_default"):
                return {
                    "has_avatar": False,
                    "is_default": True,
                    "upload_count": 0
                }
            
            # Count historical uploads (from logs/database)
            upload_count_key = f"avatar_uploads:{user_id}"
            upload_count = await cache_service.get(upload_count_key) or 0
            
            return {
                "has_avatar": True,
                "is_default": False,
                "format": avatar_data.get("format"),
                "file_size": avatar_data.get("file_size"),
                "uploaded_at": avatar_data.get("uploaded_at"),
                "upload_count": upload_count
            }
        
        except Exception as e:
            logger.error(f"Failed to get avatar stats: {str(e)}")
            return {}


# Singleton instance
avatar_service = AvatarService()