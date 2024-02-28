
using Blazored.LocalStorage;

namespace ClientLibrary.Helpers
{ 
    public class LocalStorageService(ILocalStorageService localStorageService) 
    {
        private const string StorageKey = "authentication-token";
        public async Task<string> GetToken() => await localStorageService.GetItemAsStringAsync(StorageKey); 
        public async Task SetToken(string Item) => await localStorageService.SetItemAsStringAsync(StorageKey, Item);
        public async Task RemoveToken() => await localStorageService.RemoveItemAsync(StorageKey);
    }
}
