set -e
docker_host=nextbillionai
image_name=gateway-keys

version=$CI_COMMIT_TAG
docker build -t $docker_host/$image_name:$version .
docker push $docker_host/$image_name:$version
exit 0
