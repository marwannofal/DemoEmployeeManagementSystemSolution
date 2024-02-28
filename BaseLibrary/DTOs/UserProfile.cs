using System.ComponentModel.DataAnnotations;
namespace BaseLibrary.DTOs
{
    public class UserProfile
    {
        [Required]
        public string Id { get; set; } = string.Empty;
        [Required]
        public string Name { get; set; } = string.Empty;
        [Required, EmailAddress, DataType(DataType.EmailAddress)]
        public string Email { get; set; } = string.Empty;
        public string Image { get; set; } = "../images/profile/defaultprofileimage.png";
    }
}
