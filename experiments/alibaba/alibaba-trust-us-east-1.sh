#!/bin/sh
CURPATH=`pwd`
TOKEN=`curl -s -X PUT -H "X-aliyun-ecs-metadata-token-ttl-seconds: 120" "http://100.100.100.200/latest/api/token"`
REGION_ID=`curl -s --retry 1 --max-time 3 -H "X-aliyun-ecs-metadata-token: $token" http://100.100.100.200/latest/meta-data/region-id`
PROCESSOR=`uname -m`
VERSION=""
TRUSTAGENT_UPDATE_SITE1=http://trustclient-${REGION_ID}.oss-${REGION_ID}-internal.aliyuncs.com
TRUSTAGENT_UPDATE_SITE2=http://trustclient-${REGION_ID}.oss-${REGION_ID}.aliyuncs.com
TRUSTAGENT_UPDATE_SITE3=http://t-trustclient-${REGION_ID}.oss-${REGION_ID}-internal.aliyuncs.com

get_last_version()
{
  echo "get last version from 1"
  HTTP_CODE=`curl -IsL -w "%{http_code}\n" --retry 1 --max-time 3 "${TRUSTAGENT_UPDATE_SITE1}""$1" -o /dev/null`
  if [ ${HTTP_CODE} -eq 200 ]; then
    VERSION=`curl -s --retry 1 --max-time 3 "${TRUSTAGENT_UPDATE_SITE1}""$1"`
    return 1
  fi
  echo "get last version from 2"
  HTTP_CODE=`curl -IsL -w "%{http_code}\n" --retry 1 --max-time 3 "${TRUSTAGENT_UPDATE_SITE2}""$1" -o /dev/null`
  if [ ${HTTP_CODE} -eq 200 ]; then
    VERSION=`curl -s --retry 1 --max-time 3 "${TRUSTAGENT_UPDATE_SITE2}""$1"`
    return 2
  fi
  echo "get last version from 3"
  HTTP_CODE=`curl -IsL -w "%{http_code}\n" --retry 1 --max-time 3 "${TRUSTAGENT_UPDATE_SITE2}""$1" -o /dev/null`
  if [ ${HTTP_CODE} -eq 200 ]; then
    VERSION=`curl -s --retry 1 --max-time 3 "${TRUSTAGENT_UPDATE_SITE3}""$1"`
    return 3
  fi
  echo "get last version error" 1>&2
  exit 1
}

download_file()
{
  echo "download from 1"
  wget -q -t 1 -T 5 "${TRUSTAGENT_UPDATE_SITE1}""$1" -O "$2"
  if [ $? -eq 0 ]; then
    return 1
  fi
  echo "download from 2"
  wget -q -t 1 -T 5 "${TRUSTAGENT_UPDATE_SITE2}""$1" -O "$2"
  if [ $? -eq 0 ]; then
    return 2
  fi
  echo "download from 3"
  wget  -q -t 1 -T 5 "${TRUSTAGENT_UPDATE_SITE3}""$1" -O "$2"
  if [ $? -eq 0 ]; then
    return 3
  fi
  rm -rf "$2"
  echo "download file error" 1>&2
  exit 1
}

install_agent_centos()
{
  RPM_NAME="t-trustclient.bin.rpm"
  RPM_MD5="t-trustclient.bin.rpm.md5"

  echo "downloading package version..."
  get_last_version "/version/${PROCESSOR}/last"
  echo "downloading package install..."
  download_file "/download/linux/centos/${PROCESSOR}/${VERSION}/t-trustclient-${VERSION}-${PROCESSOR}.rpm" "${RPM_NAME}"
  echo "downloading package checksum..."
  download_file "/download/linux/centos/${PROCESSOR}/${VERSION}/t-trustclient-${VERSION}-${PROCESSOR}.rpm.md5" "${RPM_MD5}"

  echo "checking package file..."
  md5_check=`md5sum "${RPM_NAME}" | awk '{print $1}' `
  md5_server=`head -1 "${RPM_MD5}" | awk '{print $1}'`
  if [ "$md5_check"x = "$md5_server"x ]
  then
    echo "check package success"

    cd ${CURPATH}
    chmod +x "${RPM_NAME}"
    yum install -y "${RPM_NAME}"
    if [ $? -eq 0 ]; then
      echo "start trust agent..."
      systemctl enable t-trustclient.service &>/dev/null
      systemctl start t-trustclient.service &>/dev/null
      if [ $? -eq 0 ]; then
        echo "TrustAgent OK."
      fi
    fi
  else
    echo "checksum error";
    exit 1
  fi

  rm -f "${RPM_MD5}"
  rm -f "${RPM_NAME}"
}

install_agent_ubuntu()
{
  DEB_NAME="t-trustclient.bin.deb"
  DEB_MD5="t-trustclient.bin.deb.md5"

  echo "downloading package version..."
  get_last_version "/version/${PROCESSOR}/last"
  echo "downloading package install..."
  download_file "/download/linux/ubuntu/${PROCESSOR}/${VERSION}/t-trustclient-${VERSION}-${PROCESSOR}.deb" "${DEB_NAME}"
  echo "downloading package checksum..."
  download_file "/download/linux/ubuntu/${PROCESSOR}/${VERSION}/t-trustclient-${VERSION}-${PROCESSOR}.deb.md5" "${DEB_MD5}"

  echo "checking package file..."
  md5_check=`md5sum "${DEB_NAME}" | awk '{print $1}' `
  md5_server=`head -1 "${DEB_MD5}" | awk '{print $1}'`
  if [ "$md5_check"x = "$md5_server"x ]
  then
    echo "check package success"

    cd ${CURPATH}
    chmod +x "${DEB_NAME}"
    dpkg -i "${DEB_NAME}"
    if [ $? -eq 0 ]; then
      echo "start trust agent..."
      systemctl enable t-trustclient.service &>/dev/null
      systemctl start t-trustclient.service &>/dev/null
      if [ $? -eq 0 ]; then
        echo "TrustAgent OK."
      fi
    fi
  else
    echo "checksum error";
    exit 1
  fi

  rm -f "${DEB_MD5}"
  rm -f "${DEB_NAME}"
}

if lsb_release -d | grep -q -e "Ubuntu" -e "Debian"; then
  install_agent_ubuntu
elif lsb_release -d | grep -q -e "Alibaba Cloud Linux" -e "CentOS" -e "Anolis"; then
  install_agent_centos
else
  echo "Unsupported Image!!!"
  exit 1
fi

exit 0
