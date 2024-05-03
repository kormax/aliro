# Aliro


<p float="left">
 <img src="./assets/IS.THIS.REAL.webp" alt="![Video depicting an Aliro credential being read, this video hasn't been doctored, but there are tricks involved in making it]" width=200px>
</p>
<sub>Please, don't freak out about the video.</sub>  

> [!NOTE]  
> Aliro protocol is under development and has a 2025 release target. No publicly known implementations are available to users yet.
> 
> This repository serves as a collection of all technical and non-technical information available at this moment. It has a big potential of becoming obsolete in the near future, considering the good track record of CSA in regards to opening up access to their specifications.
> 


# Overview

## Introduction

Aliro is a standardized communication protocol between access readers and user devices;



## Development

The standard is developed by the Connectivity Standards Alliance (CSA) - an organization responsible for the creation of Matter specification.

The companies listed as members of the work group are:
* Consumer device manufacturers:
  - Apple;
  - Google;
  - Samsung;
* Hardware component manufacturers:
  - NXP;
  - ST;
  - Infineon;
* Access control system manufacturers:
  - HID;
  - Allegion.


## Features

The following additional features of Aliro have been mentioned in one way or another, or have been synthesized based on known technical information:

- Sharing `EvictableEndpoint`:
  - "Offline" sharing;
- Automatic generation of credentials for devices added into Matter home installation  `Issuer -> UnevictableEndpoint`;
- Limitations upon credentials:
  - Time of the day;
  - Day of the week;
  - Limited use (date or count);
  - Additional authentication requirements;
- Cross-platform compatibility;
- Multiple readers per installation;
- Multiple radio technologies:
  - NFC;
  - BLE + UWB;

One thing to keep in mind is that the mention of any of those features does not mean that they'll end up in the final release of the specification, or if a particular OEM is in the right mood to implement all of them:
  - With Car and Home keys, the protocol seemingly offers support for requesting strong authentication (aka, no express mode). Apple devices ignore that parameter and authenticate anyway;
  - With Car Keys, one implementation "should" work on all devices and platforms, but there have been cases of a particular manufacturer being compatible with one platform and not the other, potentially as a result of the de-facto requirement to make a deal with each OEM separately.


## Release date

Aliro does not have an official release date, but some public sources related to CSA have reported that Aliro is targeting 2025 release.

Meanwhile, starting from Spring 2024, internal code of different OEMs had started to gain references to Aliro:

- Android 15 source code gained UWB implementation;
- Google Play Services gained references to Aliro HCE service;
- IOS 17.5 contains Matter support headers related to Aliro lock configuration and credential provisioning;
- IOS might contain references to Aliro (or plain UnifiedAccess, which the Aliro is derivative of) under the "Hydra" codename.

Considering the fact that parts of code related to Aliro has been shipped to customer devices in those cases, means that the protocol implementation is already undergoing active testing.  
There's a non-zero chance of Google mentioning Aliro on Google IO in May, or Apple at WWDC in June.

Taking a broad guess, we could see Aliro releasing anywhen starting from Summer 2024 (as a developer preview, if specification is opened), up to Autumn 2024 (when Android 15, IOS 18 release, alongside their respective flagship devices), or Winter 2024/2025.

Considering that Aliro is intended for both residential and commercial access control, it's also possible that the residential part of the spec gets released earlier, while the access control side could be delayed to add or refine features required in those cases.


# Technical details


## Communication modes

Aliro specification covers two modes of communication between the reader and the endpoint:
- NFC;
- BLE + UWB.

While the NFC part of the specification will be mandatory, BLE + UWB for passive entry will be optional.

The standard does not specify how the reader is to communicate or integrate with the outside world, so it may use any of the following:
* Wired: Ethernet, OSDP, Wiegand, etc.
* Wireless: Pure BLE, WiFi, Thread, ZigBee.


## Matter integration

While Aliro specifically mentions lack of any limitations on how the reader integrates with the external world, it doesn't mean that the reverse is true.

Matter protocol will feature direct integration with Aliro-compatible hardware. [First pull requests that include references to Aliro have hit the connectedhomeip repository as early as this January](https://github.com/project-chip/connectedhomeip/pull/31144/files).



## NFC


### ECP and PLF

There is no information in regards to the use of Enhanced Contactless Polling or Polling Loop Filters with Aliro.  
Considering that Apple had historically used ECP for all* express-mode-enabled passes and that Google is steamrolling PLF implementation into Android 15's NFC stack, there's a high chance that both device groups will employ the use of their respective polling augmentation technology alongside Aliro.

What poses a question is whether NFC polling augmentation will fall outside the Aliro specification and become a matter of direct agreement between each hardware manufacturer and Apple and Google, or if both sides may opt to support each other's technologies or even share a common data format for ideal interoperability.

### Applets and Application Identifiers

According tho the fresh (May) release of Google Play Services, Aliro will use two application identifiers:
1. Primary:  
  `A000000909ACCE5501`
2. Secondary:  
   `A000000909ACCE5502`

Those who are familiar with the `UnifiedAccess` family of NFC protocols, know that the so-similar two-app-combo is also used by:
- Digital Car Keys;
- Apple Home Keys;
- Apple Access Keys.

Where:
- The first applet is hosted on the secure element (SE), and is responsible for storing the credential data and performing authentication.
- Second one is hosted by the operating system (HCE), and is used for credential enrollment and/or storage of auxiliary data.


What's unique about this implementation, is that this time both AID entries are declared as having an on-host implementation.
This could mean one of the following:
- Aliro, unlike other `UnifiedAccess`-derivative protocols, will allow the use of HCE, perhaps with one of the following specifics:
  * There are no restrictions on how credential data is stored;
  * Credential data must be stored at least in semi-secure location, like on the TEE;
  * Credential data must be located in the secure/external hardware, specifics on if the secure hardware must be connected directly to radio or can access radio indirectly through a CPU + Software don't matter. StrongBox Keymaster could be an example of an implementation meeting this criteria, as it stores key data in a secure element, but cryptographic operations are performed on behalf of the operating system.   
- HCE is used by Google internally for testing purposes only. In this case, it would also mean that the cool `ACE55` AID affixes might not be used;

All of these theories have an equal chance of being true, considering that Aliro might sidestep some limitations similar to the ones enforced by Car Key spec in order to get much broader support, as there are still many Android devices lacking a dedicated SE, let alone an "Android Ready SE" compatible one, but there are lots that contain a TEE, which can also be used for similar purposes, even if not considered as secure, while being miles better than plain OS-level software-based implementation.  

Regardless of that, SE-backed implementation will surely be an option and used by Apple. It also might be available for premium Android devices, in order to allow operation in low battery situations, but at this moment there are no clues leading to that.



## UWB

Android 15 source code features many references to Aliro in regards to the UWB specification. 

[The codebase](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/Uwb/service/support_lib/src/com/google/uwb/support/aliro/) features following classes:
- AliroOpenRangingParams
- AliroParams
- AliroProtocolVersion
- AliroPulseShapeCombo
- AliroRangingError
- AliroRangingReconfiguredParams
- AliroRangingStartedParams
- AliroRangingStoppedParams
- AliroSpecificationParams
- AliroStartRangingParams

Going to the parent directory, we see a `ccc` directory, dedicated to Car Connectivity Consortium's Digital Car Key UWB implementation. The directory contains:
- CccOpenRangingParams
- CccParams
- ... We can stop at this point;

As we can see, the directory structure and even the class name patterns are exactly the same. The file contents are different due to different class and variable names, but no substantial differences have been found.


This information serves as an additional clue to the fact that Aliro is based on the `UnifiedAccess` family of protocols.


## Protocol and cryptography

Thanks to the Matter GitHub repository and IOS 17.5 runtime headers, we know that the following cryptographic data will be used with the protocol:


````
 request struct SetAliroReaderConfigRequest {
    octet_string<32> signingKey = 0;
    octet_string<65> verificationKey = 1;
    octet_string<16> groupIdentifier = 2;
    optional octet_string<16> groupResolvingKey = 3;
}
````

To get more clues, we should draw some parallels with  `UnifiedAccess` protocol:

- We can immediately recognize the `signingKey`, which is a direct counterpart of the `privateKey`, used by the reader to prove to the device that transaction ephemeral data was generated by a trusted device.

- Verification key `verificationKey` is 65 bytes long, which is the number of bytes that a EC public key takes. This key is unique in this protocol. Taking a guess, a private portion of that key could be injected into all credentials, so that a device could also prove that its ephemeral data is valid, even before the final signature done by the device over the encrypted channel.
- Group identifier allows the resolution of which particular credential is to be used;
- Group resolving key could be related to BLE identity resolving key `IRK`;


Considering that there are many common pieces, that's a strong indication that Aliro will have the same or slightly augmented variations of `FAST -> STANDARD -> EXCHANGE` command flow;



# References

* General 
  - [CSA Aliro](https://csa-iot.org/all-solutions/aliro/) - landing page providing a general overview of the standard without any technical specifics.
  - [Aliro Executive Overview](https://csa-iot.org/wp-content/uploads/2024/03/Aliro-Executive-Overview.pdf);
  - [Android Ready SE Alliance](https://developers.google.com/android/security/android-ready-se).
* Technical resources:
  - [GitHub Matter Repository](https://github.com/project-chip/connectedhomeip) - contains snippets of code related to Aliro;
  - [Android Code Search](https://cs.android.com/search?q=aliro&sq=) - contains Aliro UWB implementation;
  - [Android StrongBox Keymaster](https://source.android.com/docs/security/features/keystore);
  - [Android Polling Loop Filters - CardEmulation, PollingFrame](https://developer.android.com/reference/android/nfc/cardemulation/package-summary);
  - [Apple Enhanced Contactless Polling (Unofficial, detailed)](https://github.com/kormax/apple-enhanced-contactless-polling);
  - [Apple Enhanced Contactless Polling (Official, very brief)](https://register.apple.com/resources/docs/apple-pay/access/program-guide/requirements/#enhanced-contactless-polling-ecp-protocol);
  - [GitHub Matter - Aliro Pull Request](https://github.com/project-chip/connectedhomeip/pull/31144/files);
  - [Apple Home Key - UnifiedAccess protocol implementation (Unofficial)](https://github.com/kormax/apple-home-key) - in-depth look at the Home Key and Unified Access protocol.