#include <nativedns/interception.hpp>
namespace nd {
std::unique_ptr<IInterceptionProvider> make_platform_interception(Config config,Logger& logger,uint16_t port){
    return std::make_unique<WinDivertInterception>(std::move(config),logger,port);
}
}
