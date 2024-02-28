
namespace BaseLibrary.Responses
{
    public record LoginResponse

        (bool Flag, string Massage = null!, string Token = null!, string refreshToken = null);

}
