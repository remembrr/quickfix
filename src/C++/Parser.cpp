/****************************************************************************
** Copyright (c) 2001-2014
**
** This file is part of the QuickFIX FIX Engine
**
** This file may be distributed under the terms of the quickfixengine.org
** license as defined by quickfixengine.org and appearing in the file
** LICENSE included in the packaging of this file.
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** See http://www.quickfixengine.org/LICENSE for licensing information.
**
** Contact ask@quickfixengine.org if any conditions of this licensing are
** not clear to you.
**
****************************************************************************/

#ifdef _MSC_VER
#include "stdafx.h"
#else
#include "config.h"
#endif

#include "FieldConvertors.h"
#include "Parser.h"
#include "Utility.h"
#include <algorithm>

namespace FIX {
bool Parser::extractLength(int &length, std::string::size_type &pos, const std::string &buffer)
    EXCEPT(MessageParseError) {
  if (!buffer.size()) {
    return false;
  }

  std::string::size_type startPos = buffer.find("\0019=", 0);
  if (startPos == std::string::npos) {
    return false;
  }
  startPos += 3;
  std::string::size_type endPos = buffer.find("\001", startPos);
  if (endPos == std::string::npos) {
    return false;
  }

  std::string strLength(buffer, startPos, endPos - startPos);

  try {
    length = IntConvertor::convert(strLength);
    if (length < 0) {
      throw MessageParseError();
    }
  } catch (FieldConvertError &) {
    throw MessageParseError();
  }

  pos = endPos + 1;
  return true;
}

bool Parser::readFixMessage(std::string &str) EXCEPT(MessageParseError) {
  std::string::size_type pos = 0;

  if (m_buffer.length() < 2) {
    return false;
  }
  pos = m_buffer.find("8=");
  if (pos == std::string::npos) {
    return false;
  }
  m_buffer.erase(0, pos);

  int length = 0;

  try {
    if (extractLength(length, pos, m_buffer)) {
      std::string::size_type bodyStart = pos;
      pos += length;

      // Need the SOH that terminates the final body field (at pos - 1) plus the
      // three bytes of the "10=" CheckSum tag before we can decide the frame.
      if (pos < 1 || pos + 3 > m_buffer.size()) {
        return false;
      }

      // GHSA-8f9j-mq72-p663 (CWE-444): the CheckSum field MUST begin exactly at
      // the BodyLength-derived boundary. The previous implementation searched
      // forward for "\00110=", which accepted a CheckSum tag appearing *after*
      // the boundary and let framing, validation and application-level reads
      // operate over different byte ranges of the same input (message smuggling
      // / parser desynchronization). Require an exact boundary match and treat
      // any deviation as a hard frame error.
      if (m_buffer[pos - 1] != '\001' || m_buffer.compare(pos, 3, "10=") != 0) {
        pos = bodyStart; // catch below discards exactly [0, bodyStart + length)
        throw MessageParseError();
      }

      pos += 3; // advance past "10="
      pos = m_buffer.find("\001", pos);
      if (pos == std::string::npos) {
        return false;
      }
      pos += 1;

      str.assign(m_buffer, 0, pos);
      m_buffer.erase(0, pos);
      return true;
    }
  } catch (MessageParseError &e) {
    if (length > 0) {
      m_buffer.erase(0, pos + length);
    } else {
      m_buffer.erase();
    }

    throw e;
  }

  return false;
}
} // namespace FIX
